# Usage

## Prerequisites

- Python 3.8+
- Install dependencies:

```bash
pip install -r requirements.txt
```

On some systems `coincurve` requires libsecp256k1. If wheels are unavailable, your package manager may provide it (e.g., `sudo apt install -y libsecp256k1-dev`).

---

## Bitcoin scanner

```bash
python3 CMD_1.4-BTC.py
```

- Logs hits to `ValidWalletsBTC.txt`.
- Prints running page count in-place.

## Ethereum scanner

```bash
python3 CMD_1.4-ETH.py
```

- Prompts for thread count (not used in v1.4).
- Logs hits to `ValidWalletsETH.txt`.

---

## Key-combination search (research tool)

See `docs/key-combination.md` for detailed instructions. Quick example:

```bash
python3 tools/find_key_combination.py \
  --key-files keys_part1.txt keys_part2.txt \
  --targets-file targets.txt \
  --k 3
```

- `keys_part*.txt`: Newline-separated private keys (hex like `0x...` or 64-hex chars, or decimal).
- `targets.txt`: Newline-separated public keys in hex (compressed 33-byte or uncompressed 65-byte). The tool normalizes to compressed.