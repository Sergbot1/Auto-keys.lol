#!/usr/bin/env python3
import argparse
import binascii
import itertools
import math
import os
import sys
from typing import Iterable, List, Sequence, Tuple, Dict, Optional

try:
    from coincurve import PublicKey, PrivateKey
except Exception as exc:
    print("Error: coincurve is required. Install with: pip install coincurve", file=sys.stderr)
    raise

# Order of the secp256k1 curve
SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


def parse_int_maybe_hex(value: str) -> Optional[int]:
    s = value.strip().lower()
    if not s:
        return None
    try:
        if s.startswith("0x"):
            return int(s, 16)
        # If it's hex-looking and length <= 64, try hex first
        if all(c in "0123456789abcdef" for c in s) and len(s) <= 66 and not s.isdigit():
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return None


def normalize_privkey(priv_int: int) -> Optional[int]:
    if priv_int is None:
        return None
    priv_int %= SECP256K1_ORDER
    if priv_int == 0:
        return None
    return priv_int


def load_private_keys_from_files(paths: Sequence[str]) -> List[int]:
    private_keys: List[int] = []
    for path in paths:
        if not os.path.exists(path):
            print(f"Warning: path not found: {path}", file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                candidate = parse_int_maybe_hex(line)
                if candidate is None:
                    continue
                normalized = normalize_privkey(candidate)
                if normalized is None:
                    continue
                private_keys.append(normalized)
    return private_keys


def priv_to_pub_compressed(priv_int: int) -> bytes:
    pk = PrivateKey(priv_int.to_bytes(32, byteorder="big"))
    return pk.public_key.format(compressed=True)


def public_key_combine_compressed(points: Sequence[bytes]) -> bytes:
    if not points:
        raise ValueError("Cannot combine zero points (identity element is not representable here)")
    pubkeys = [PublicKey(p) if not isinstance(p, PublicKey) else p for p in points]
    combined = PublicKey.combine_keys(pubkeys)
    return combined.format(compressed=True)


def negate_compressed_point(point: bytes) -> bytes:
    if len(point) != 33 or point[0] not in (2, 3):
        raise ValueError("Expected a 33-byte compressed public key")
    # Flip the prefix: 0x02 <-> 0x03
    flipped_prefix = 0x02 if point[0] == 0x03 else 0x03
    return bytes([flipped_prefix]) + point[1:]


def parse_pubkey_hex(line: str) -> Optional[bytes]:
    s = line.strip().lower()
    if not s:
        return None
    if s.startswith("0x"):
        s = s[2:]
    try:
        data = binascii.unhexlify(s)
    except binascii.Error:
        return None
    try:
        pub = PublicKey(data)
        return pub.format(compressed=True)
    except Exception:
        return None


def load_target_pubkeys(targets_file: Optional[str], targets_inline: Sequence[str]) -> List[bytes]:
    pubkeys: List[bytes] = []
    if targets_file:
        with open(targets_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pk = parse_pubkey_hex(line)
                if pk is not None:
                    pubkeys.append(pk)
    for t in targets_inline:
        pk = parse_pubkey_hex(t)
        if pk is not None:
            pubkeys.append(pk)
    # Deduplicate
    unique = []
    seen = set()
    for p in pubkeys:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def sum_of_subset_points(points: Sequence[bytes]) -> bytes:
    if not points:
        raise ValueError("Empty subset has no explicit point representation")
    if len(points) == 1:
        return points[0]
    return public_key_combine_compressed(points)


def iter_subset_sums(pubkeys: Sequence[bytes], indices: Sequence[int], subset_size: int) -> Iterable[Tuple[str, Tuple[int, ...]]]:
    for combo in itertools.combinations(indices, subset_size):
        pts = [pubkeys[i] for i in combo]
        combined = sum_of_subset_points(pts)
        yield combined.hex(), combo


def estimate_total_combinations(n_left: int, n_right: int, k: int) -> int:
    total = 0
    for i in range(max(0, k - n_right), min(k, n_left) + 1):
        total += math.comb(n_left, i) * math.comb(n_right, k - i)
    return total


def find_key_combinations(private_keys: Sequence[int], target_pubkeys: Sequence[bytes], k: int, find_all: bool = False, max_combinations_warn: int = 5_000_000) -> List[Tuple[bytes, Tuple[int, ...]]]:
    if k < 1:
        raise ValueError("k must be >= 1")
    if len(private_keys) < k:
        raise ValueError("Not enough private keys for the requested combination size")

    # Precompute public keys (compressed)
    pubkeys: List[bytes] = [priv_to_pub_compressed(p) for p in private_keys]

    mid = len(pubkeys) // 2
    left_indices = list(range(0, mid))
    right_indices = list(range(mid, len(pubkeys)))

    total_est = estimate_total_combinations(len(left_indices), len(right_indices), k)
    if total_est > max_combinations_warn:
        print(f"Warning: total combinations to check is large (~{total_est:,}). This may be slow.", file=sys.stderr)

    results: List[Tuple[bytes, Tuple[int, ...]]] = []

    # For each split i from left, k-i from right
    for i in range(max(0, k - len(right_indices)), min(k, len(left_indices)) + 1):
        right_size = k - i

        # Build lookup for right side only once per right_size
        right_lookup: Dict[str, Tuple[int, ...]] = {}
        if right_size == 0:
            # Represent identity implicitly by empty tuple sentinel
            right_lookup["__IDENTITY__"] = tuple()
        else:
            for sum_hex, combo in iter_subset_sums(pubkeys, right_indices, right_size):
                # Store first occurrence only
                if sum_hex not in right_lookup:
                    right_lookup[sum_hex] = combo

        # Iterate left combinations of size i
        if i == 0:
            left_combos = [tuple()]  # identity
        else:
            left_combos = list(itertools.combinations(left_indices, i))

        for left_combo in left_combos:
            if i == 0:
                left_sum_point: Optional[bytes] = None  # identity
            else:
                left_points = [pubkeys[idx] for idx in left_combo]
                left_sum_point = sum_of_subset_points(left_points)

            for target in target_pubkeys:
                if right_size == 0 and i > 0:
                    # Need left_sum == target
                    if left_sum_point is not None and left_sum_point == target:
                        # Found: left_combo only
                        results.append((target, left_combo))
                        if not find_all:
                            return results
                    continue

                if i == 0 and right_size > 0:
                    # Need right_sum == target
                    needed_hex = target.hex()
                elif i == 0 and right_size == 0:
                    # k == 0 invalid earlier; here only if k==0 which we forbid
                    continue
                else:
                    # Need right_sum = target - left_sum = target + (-left_sum)
                    neg_left = negate_compressed_point(left_sum_point)  # type: ignore[arg-type]
                    need_point = public_key_combine_compressed([target, neg_left])
                    needed_hex = need_point.hex()

                # Check in right lookup
                if right_size == 0:
                    # Identity case
                    if "__IDENTITY__" in right_lookup and needed_hex == target.hex():
                        results.append((target, left_combo))
                        if not find_all:
                            return results
                else:
                    match = right_lookup.get(needed_hex)
                    if match is not None:
                        # Combine index tuples
                        full_combo = left_combo + match
                        results.append((target, full_combo))
                        if not find_all:
                            return results

    return results


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Find subset of private keys whose sum corresponds to a target public key on secp256k1 (meet-in-the-middle)")
    parser.add_argument("--key-files", nargs="+", required=True, help="Paths to files containing private keys (hex or decimal), one per line")
    parser.add_argument("--targets-file", help="Path to file with target public keys in hex (compressed or uncompressed), one per line")
    parser.add_argument("--target", action="append", default=[], help="Inline target public key in hex (can be repeated)")
    parser.add_argument("--k", type=int, required=True, help="Exact subset size to search for")
    parser.add_argument("--find-all", action="store_true", help="Find all solutions (default: stop at first)")
    parser.add_argument("--max-combinations-warn", type=int, default=5_000_000, help="Warn if estimated combinations exceed this number")

    args = parser.parse_args(argv)

    private_keys = load_private_keys_from_files(args.key_files)
    if not private_keys:
        print("No private keys loaded.", file=sys.stderr)
        return 2

    targets = load_target_pubkeys(args.targets_file, args.target)
    if not targets:
        print("No target public keys provided.", file=sys.stderr)
        return 2

    results = find_key_combinations(private_keys, targets, args.k, find_all=args.find_all, max_combinations_warn=args.max_combinations_warn)

    if not results:
        print("No combinations found.")
        return 1

    for target, combo in results:
        combo_indices = list(combo)
        combo_privs = [private_keys[i] for i in combo_indices]
        s = sum(combo_privs) % SECP256K1_ORDER
        s_pub = PrivateKey(s.to_bytes(32, "big")).public_key.format(compressed=True)
        print("Found match for target:", target.hex())
        print("Subset size k:", len(combo_indices))
        print("Indices:", combo_indices)
        print("Private keys (hex):", [hex(v)[2:].zfill(64) for v in combo_privs])
        print("Sum private key (hex):", hex(s)[2:].zfill(64))
        print("Sum public key (compressed):", s_pub.hex())
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())