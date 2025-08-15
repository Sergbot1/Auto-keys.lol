# Project Overview

This repository contains simple command-line scripts that scan `keys.lol` pages for balances and log hits, plus an optional research tool for elliptic-curve key-combination analysis.

Components:
- `CMD_1.4-BTC.py`: Randomly scans Bitcoin pages on `keys.lol` and logs pages containing non-zero BTC balances.
- `CMD_1.4-ETH.py`: Randomly scans Ethereum pages on `keys.lol` and logs pages containing non-zero ETH balances.
- `tools/find_key_combination.py`: Meet-in-the-middle tool to find a subset of private keys whose modular sum corresponds to a given secp256k1 public key.

Use cases (research only):
- Crypto key-generation analysis and education.
- Bitcoin/Ethereum key-space research and simulations.

Read next:
- Usage: see `docs/usage.md`.
- APIs and internals: see `docs/api.md`.
- Key-combination research tool: see `docs/key-combination.md`.