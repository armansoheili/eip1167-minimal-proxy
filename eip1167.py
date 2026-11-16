"""EIP-1167 minimal proxy (clone) factory simulator in pure Python.

A *minimal proxy* (EIP-1167) is a 45-byte contract that forwards every call
to a single implementation contract via ``delegatecall``.  Deploying a clone
costs far less gas than deploying a full copy of the logic, and every clone
shares the implementation's code while keeping its own storage -- the
standard pattern behind cheap per-user wallets, per-token vaults and
factory-spawned ERC-20s.

This module simulates the whole flow with zero dependencies:

* ``keccak_256`` -- self-contained Keccak-256 (the hash Ethereum uses,
  *not* NIST SHA3-256), verified against the empty-string and ``"abc"``
  vectors below.
* ``clone_runtime_code`` / ``clone_init_code`` -- the exact 45-byte
  EIP-1167 bytecode for a given implementation address.
* ``rlp_encode`` -- the minimal RLP codec needed for address derivation.
* ``create_address`` / ``create2_address`` -- CREATE and CREATE2 address
  prediction (EIP-1014).
* ``Counter`` -- a toy logic contract whose methods run against a clone's
  own storage dict, exactly like a ``delegatecall``.
* ``CloneFactory`` -- a factory that predicts, deploys and calls clones,
  tracking a CREATE nonce per deployer.

Run the demo::

    $ python3 eip1167.py --demo

Run the self-tests::

    $ python3 eip1167.py --test
"""

from __future__ import annotations

__all__ = [
    "keccak_256",
    "to_checksum_address",
    "clone_runtime_code",
    "clone_init_code",
    "rlp_encode",
    "create_address",
    "create2_address",
    "Counter",
    "CloneFactory",
]

_MASK64 = (1 << 64) - 1

# ---------------------------------------------------------------------------
# Keccak-256 (Keccak-f[1600], rate 1088 bits, pad10*1 with domain byte 0x01)
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(state: list[int]) -> list[int]:
    for rnd in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
             ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho + Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _R[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ (~b[(x + 1) % 5 + 5 * y]
                                       & b[(x + 2) % 5 + 5 * y]))
        # Iota
        state[0] ^= _RC[rnd]
    return state


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 digest of ``data``.

    >>> keccak_256(b"").hex()
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    >>> keccak_256(b"abc").hex()
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    """
    state = [0] * 25
    rate = 136  # bytes (1088 bits)
    buf = bytearray(data)
    buf.append(0x01)  # pad10*1
    while len(buf) % rate:
        buf.append(0x00)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        block = buf[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

def _addr_bytes(address: str) -> bytes:
    if address.startswith(("0x", "0X")):
        address = address[2:]
    raw = bytes.fromhex(address)
    if len(raw) != 20:
        raise ValueError(f"address must be 20 bytes, got {len(raw)}")
    return raw


def to_checksum_address(address: str) -> str:
    """EIP-55 checksummed form of ``address``.

    The hash is taken over the lowercase *hex string* of the address
    (40 ASCII characters), not over the raw 20 bytes.

    >>> to_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
    >>> to_checksum_address("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359'
    >>> to_checksum_address("0x0000000000000000000000000000000000000000")
    '0x0000000000000000000000000000000000000000'
    """
    raw = _addr_bytes(address)
    h = keccak_256(raw.hex().encode("ascii")).hex()
    out = [ch.upper() if int(h[i], 16) >= 8 else ch for i, ch in enumerate(raw.hex())]
    return "0x" + "".join(out)


# ---------------------------------------------------------------------------
# EIP-1167 clone bytecode
# ---------------------------------------------------------------------------

_CLONE_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_CLONE_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


def clone_runtime_code(implementation: str) -> bytes:
    """The 45-byte EIP-1167 runtime code for ``implementation``.

    Layout: ``363d3d373d3d3d363d73`` + implementation (20 bytes) +
    ``5af43d82803e903d91602b57fd5bf3`` -- i.e. ``PUSH20 <impl>`` wrapped in
    the delegatecall trampoline.

    >>> code = clone_runtime_code("0x" + "00" * 20)
    >>> len(code)
    45
    >>> code.hex() == "363d3d373d3d3d363d73" + "00" * 20 + "5af43d82803e903d91602b57fd5bf3"
    True
    >>> code[:10].hex(), code[-15:].hex()
    ('363d3d373d3d3d363d73', '5af43d82803e903d91602b57fd5bf3')
    """
    return _CLONE_PREFIX + _addr_bytes(implementation) + _CLONE_SUFFIX


def clone_init_code(implementation: str) -> bytes:
    """Creation code for a minimal proxy.

    For EIP-1167 the init code *is* the runtime code: deploying it returns
    the same 45 bytes as the deployed contract.

    >>> clone_init_code("0x" + "ab" * 20) == clone_runtime_code("0x" + "ab" * 20)
    True
    """
    return clone_runtime_code(implementation)


# ---------------------------------------------------------------------------
# Minimal RLP (only what address derivation needs)
# ---------------------------------------------------------------------------

def _rlp_encode_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) <= 55:
        return bytes([0x80 + len(data)]) + data
    ln = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(ln)]) + ln + data


def _rlp_encode_int(n: int) -> bytes:
    if n == 0:
        return b"\x80"
    return _rlp_encode_bytes(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def rlp_encode(items: list) -> bytes:
    """RLP-encode a list of ``bytes`` / ``int`` items.

    >>> rlp_encode([bytes(20), 0]).hex()
    'd694000000000000000000000000000000000000000080'
    >>> rlp_encode([b"cat", b"dog"]).hex()
    'c88363617483646f67'
    """
    payload = b"".join(_rlp_encode_bytes(i) if isinstance(i, bytes)
                       else _rlp_encode_int(i) for i in items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    ln = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(ln)]) + ln + payload


# ---------------------------------------------------------------------------
# Address prediction: CREATE and CREATE2 (EIP-1014)
# ---------------------------------------------------------------------------

def create_address(sender: str, nonce: int) -> str:
    """Address of the contract ``sender`` deploys with CREATE at ``nonce``.

    ``keccak256(rlp([sender, nonce]))[12:]`` -- the same address the
    factory's ``deploy`` returns for that nonce.

    >>> create_address("0x" + "00" * 20, 0)
    '0xBd770416a3345F91E4B34576cb804a576fa48EB1'
    >>> create_address("0x" + "00" * 20, 0) == create_address("0x" + "00" * 20, 0)
    True
    """
    if nonce < 0:
        raise ValueError("nonce must be >= 0")
    digest = keccak_256(rlp_encode([_addr_bytes(sender), nonce]))
    return to_checksum_address(digest[12:].hex())


def create2_address(deployer: str, salt: bytes, init_code: bytes) -> str:
    """CREATE2 address (EIP-1014): ``keccak256(0xff ++ deployer ++ salt ++
    keccak256(init_code))[12:]``.

    >>> impl = "0x" + "ab" * 20
    >>> a = create2_address("0x" + "11" * 20, bytes(32), clone_init_code(impl))
    >>> a == create2_address("0x" + "11" * 20, bytes(32), clone_init_code(impl))
    True
    >>> a != create_address("0x" + "11" * 20, 0)
    True
    """
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    digest = keccak_256(b"\xff" + _addr_bytes(deployer) + salt
                        + keccak_256(init_code))
    return to_checksum_address(digest[12:].hex())


# ---------------------------------------------------------------------------
# Logic contract + factory simulation
# ---------------------------------------------------------------------------

class Counter:
    """Toy logic contract: a single counter.

    Each method takes the clone's ``storage`` dict -- exactly how a
    ``delegatecall`` runs the implementation's code against the proxy's
    own storage, so every clone keeps an independent counter.

    >>> storage = {}
    >>> Counter.increment(storage)
    1
    >>> Counter.increment(storage)
    2
    >>> Counter.get(storage)
    2
    """

    @staticmethod
    def increment(storage: dict) -> int:
        storage["count"] = storage.get("count", 0) + 1
        return storage["count"]

    @staticmethod
    def get(storage: dict) -> int:
        return storage.get("count", 0)

    @staticmethod
    def reset(storage: dict) -> int:
        storage["count"] = 0
        return 0


class CloneFactory:
    """Simulates a minimal-proxy factory on one chain.

    Tracks a CREATE nonce per deployer, predicts each clone's address
    before deploying it, and keeps per-clone storage so clones share code
    but not state.

    >>> factory = CloneFactory()
    >>> impl = "0x" + "ab" * 20
    >>> deployer = "0x" + "11" * 20
    >>> factory.predict(deployer) == factory.deploy(impl, deployer)
    True
    >>> a = factory.deploy(impl, deployer)
    >>> factory.call(a, "increment")
    1
    >>> factory.call(a, "increment")
    2
    >>> factory.call(a, "get")
    2
    >>> b = factory.deploy(impl, deployer)
    >>> factory.call(b, "get")
    0
    >>> factory.implementation_of(a) == factory.implementation_of(b) == to_checksum_address(impl)
    True
    """

    def __init__(self) -> None:
        self._nonces: dict[str, int] = {}
        self._clones: dict[str, dict] = {}

    def predict(self, deployer: str, nonce: int | None = None) -> str:
        """Address the next clone from ``deployer`` will land at."""
        n = self._nonces.get(deployer.lower(), 0) if nonce is None else nonce
        return create_address(deployer, n)

    def deploy(self, implementation: str, deployer: str) -> str:
        """Deploy a clone of ``implementation`` from ``deployer``.

        Returns the clone address (equal to ``predict(deployer)`` called
        just before). The clone starts with empty storage.
        """
        nonce = self._nonces.get(deployer.lower(), 0)
        address = create_address(deployer, nonce)
        self._nonces[deployer.lower()] = nonce + 1
        self._clones[address] = {
            "implementation": to_checksum_address(implementation),
            "storage": {},
            "code": clone_runtime_code(implementation),
        }
        return address

    def deploy_create2(self, implementation: str, deployer: str,
                       salt: bytes) -> str:
        """Deploy a clone at a counterfactual CREATE2 address."""
        address = create2_address(deployer, salt, clone_init_code(implementation))
        if address in self._clones:
            raise ValueError(f"clone already deployed at {address}")
        self._clones[address] = {
            "implementation": to_checksum_address(implementation),
            "storage": {},
            "code": clone_runtime_code(implementation),
        }
        return address

    def implementation_of(self, clone: str) -> str:
        """Implementation address a clone delegates to."""
        return self._clones[to_checksum_address(clone)]["implementation"]

    def code_of(self, clone: str) -> bytes:
        """The 45-byte runtime code stored at a clone's address."""
        return self._clones[to_checksum_address(clone)]["code"]

    def call(self, clone: str, method: str, *args):
        """Call ``method`` on a clone (delegatecall into the logic)."""
        entry = self._clones[to_checksum_address(clone)]
        fn = getattr(Counter, method, None)
        if fn is None or not callable(fn):
            raise ValueError(f"unknown method {method!r}")
        return fn(entry["storage"], *args)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo() -> None:
    factory = CloneFactory()
    impl = "0x" + "ab" * 20
    deployer = "0x" + "11" * 20
    print("implementation:  ", impl)
    print("clone code (45B):", clone_runtime_code(impl).hex())
    print("predicted clone: ", factory.predict(deployer))
    a = factory.deploy(impl, deployer)
    b = factory.deploy(impl, deployer)
    print("clone A:         ", a)
    print("clone B:         ", b)
    factory.call(a, "increment")
    factory.call(a, "increment")
    factory.call(b, "increment")
    print("A count:", factory.call(a, "get"), "(expected 2)")
    print("B count:", factory.call(b, "get"), "(expected 1)")
    c = factory.deploy_create2(impl, deployer, salt=(42).to_bytes(32, "big"))
    print("CREATE2 clone:   ", c)
    print("same code, independent state: clones share the implementation,")
    print("not their storage.")


if __name__ == "__main__":
    import argparse
    import doctest

    parser = argparse.ArgumentParser(description="EIP-1167 minimal proxy simulator")
    parser.add_argument("--demo", action="store_true", help="run the demo")
    parser.add_argument("--test", action="store_true", help="run doctests")
    args = parser.parse_args()
    if args.test:
        results = doctest.testmod(verbose=False)
        print(f"{results.attempted} doctests, {results.failed} failed")
        raise SystemExit(1 if results.failed else 0)
    _demo()
