# Key-Combination Search Tool (secp256k1)

Research utility for finding a subset of private keys whose modular sum yields a private key corresponding to a target public key. This is useful for academic analysis of key aggregation, wallet shards, and studying edge-case vulnerabilities.

> Legal note: Use only with keys you own or have explicit permission to analyze.

## Problem

Given:
- A list of private keys `d1, d2, ..., dn` (integers modulo curve order).
- Target public key(s) `Q` on secp256k1.
- An integer `k`.

Find indices `{i1, ..., ik}` such that:

- `s = (di1 + ... + dik) mod n`, and
- `s * G` equals `Q` (where `G` is the secp256k1 base point).

## Algorithm

Meet-in-the-middle across two halves of the key list:
- Precompute `k1`-subset sums on the right half as public points and store in a map.
- Iterate `k2`-subset sums on the left half, compute `Q - sumLeft` as a point, and look it up in the map.
- Repeat for all `k1 + k2 = k` splits.

Pros: avoids discrete log; uses only point addition. Cons: combinatorial growth with `k` and `n`.

## Installation

```bash
pip install -r requirements.txt
```

If `coincurve` build fails, install libsecp256k1 via your OS package manager.

## Input format

- Key files: one private key per line. Supported formats:
  - Hex with or without `0x` (64 hex chars typical), or
  - Decimal integer. Values are reduced mod curve order; `0` is ignored.
- Target public keys:
  - Compressed (33-byte) or uncompressed (65-byte) hex, with or without `0x`. Internally normalized to compressed.

## CLI

```bash
python3 tools/find_key_combination.py \
  --key-files <file1> [<file2> ...] \
  [--targets-file <targets.txt>] \
  [--target <hex_pubkey>]... \
  --k <subset_size> \
  [--find-all] \
  [--max-combinations-warn 5000000]
```

- `--key-files`: one or more files containing candidate private keys.
- `--targets-file`/`--target`: provide target public keys via file and/or inline flags.
- `--k`: exact subset size to search for.
- `--find-all`: continue after the first match.

## Examples

Prepare sample data:

```bash
cat > keys_part1.txt <<'EOF'
1
2
3
EOF
cat > keys_part2.txt <<'EOF'
4
5
6
EOF
```

Pick a synthetic target: suppose we want the subset `{2, 5}` so `s=7`. Compute target pubkey with Python:

```bash
python3 - <<'PY'
from coincurve import PrivateKey
s = 7
print(PrivateKey(s.to_bytes(32,'big')).public_key.format(compressed=True).hex())
PY
```

Run search for `k=2`:

```bash
python3 tools/find_key_combination.py \
  --key-files keys_part1.txt keys_part2.txt \
  --target <paste_hex_from_above> \
  --k 2
```

Expected output (indices may differ based on file order):
- Matching target hex
- Subset indices and the corresponding private keys
- The summed private key and its public key (should equal target)

## Tips

- Keep `k` small (≤ 5–6) and candidate list moderate (≤ 40–50) to avoid explosive combinations.
- If you have structured shards (e.g., split across two files), it can improve meet-in-the-middle balance.
- For multiple targets, pass several `--target` flags or a single `--targets-file`.