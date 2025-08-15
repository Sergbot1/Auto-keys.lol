# Auto keys.lol program

This repository provides simple scripts to scan random `keys.lol` pages for balances and log the hits. It also includes a research tool for secp256k1 key-combination analysis.

- For an overview, see `docs/overview.md`.
- For API details, see `docs/api.md`.
- For usage and examples, see `docs/usage.md`.
- For the key-combination research tool, see `docs/key-combination.md`.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

If `coincurve` requires system libraries, install `libsecp256k1` via your OS package manager.

## Quick start

- Bitcoin scanner:
  ```bash
  python3 CMD_1.4-BTC.py
  ```
- Ethereum scanner:
  ```bash
  python3 CMD_1.4-ETH.py
  ```
- Key-combination search (example):
  ```bash
  python3 tools/find_key_combination.py \
    --key-files keys_part1.txt keys_part2.txt \
    --targets-file targets.txt \
    --k 3
  ```

## Version 1.4 notes
- Removed multi-threading and optimized the algorithm for speed.
