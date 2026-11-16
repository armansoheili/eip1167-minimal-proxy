# eip1167-minimal-proxy

EIP-1167 minimal proxy (clone) factory simulator in pure Python — zero dependencies.

A *minimal proxy* is a 45-byte contract that forwards every call to a single
implementation contract via `delegatecall`. Deploying a clone costs far less
gas than deploying a full copy of the logic, and every clone shares the
implementation's code while keeping its own storage. It is the standard
pattern behind cheap per-user wallets, per-token vaults and factory-spawned
tokens.

## What is in here

- `keccak_256` — self-contained Keccak-256 (the hash Ethereum uses, *not*
  NIST SHA3-256). Verified against the empty-string, `"abc"` and `"test"`
  vectors.
- `to_checksum_address` — EIP-55 checksumming (hash is over the lowercase
  hex string). Verified against all four EIP-55 spec test vectors.
- `clone_runtime_code` / `clone_init_code` — the exact 45-byte EIP-1167
  bytecode for a given implementation address (`363d3d373d3d3d363d73` +
  implementation + `5af43d82803e903d91602b57fd5bf3`).
- `rlp_encode` — the minimal RLP codec needed for address derivation.
- `create_address` / `create2_address` — CREATE and CREATE2 (EIP-1014)
  address prediction.
- `Counter` — a toy logic contract whose methods run against a clone's own
  storage dict, exactly like a `delegatecall`.
- `CloneFactory` — a factory that predicts, deploys and calls clones,
  tracking a CREATE nonce per deployer.

## Usage

```python
from eip1167 import CloneFactory, clone_runtime_code, create2_address

factory = CloneFactory()
impl = "0x" + "ab" * 20          # the logic contract
deployer = "0x" + "11" * 20     # the factory account

factory.predict(deployer)       # address the next clone will land at
a = factory.deploy(impl, deployer)
b = factory.deploy(impl, deployer)

factory.call(a, "increment")    # 1
factory.call(a, "increment")    # 2
factory.call(b, "increment")    # 1 -- same code, independent state

clone_runtime_code(impl).hex()  # the 45-byte proxy bytecode
create2_address(deployer, (42).to_bytes(32, "big"), clone_runtime_code(impl))
```

## Demo

```
$ python3 eip1167.py --demo
implementation:   0xabababababababababababababababababababab
clone code (45B): 363d3d373d3d3d363d73abababababababababababababababababababab5af43d82803e903d91602b57fd5bf3
predicted clone:  0x8F7a45eBDe059392E46A46DCc14AB24681A961Ea
clone A:          0x8F7a45eBDe059392E46A46DCc14AB24681A961Ea
clone B:          0x15452EC016c4dc8c549E7fe6Ff4b26324Ea8b7A4
A count: 2 (expected 2)
B count: 1 (expected 1)
CREATE2 clone:    0x3CaaE5F95aF9A033F9E2CE618eFeF5a5bB06BC29
same code, independent state: clones share the implementation,
not their storage.
```

## Tests

```
$ python3 eip1167.py --test
33 doctests, 0 failed
```

## Files

- `eip1167.py` — the whole simulator (Keccak-256, EIP-55, RLP, CREATE/CREATE2
  prediction, `Counter` logic contract, `CloneFactory`)
- `README.md` — this file
