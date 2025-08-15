import os
import itertools
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Set, Tuple

from fastecdsa import curve
from fastecdsa.encoding.sec1 import SEC1Encoder


HexKey = str
ParsedKey = Tuple[int, HexKey]


class KeySearcher:
    def __init__(self):
        self._setup_logging()
        self.target_file: str = "X.txt"
        self.output_file: str = "matches.txt"
        self.key_files: List[str] = self._get_key_files()
        self.found_count: int = 0

    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )

    def _get_key_files(self) -> List[str]:
        """Locate key files named X1.txt, X2.txt, ... in current dir."""
        files: List[str] = []
        i: int = 1
        while os.path.exists(f"X{i}.txt"):
            files.append(f"X{i}.txt")
            i += 1
        if not files:
            logging.error("No key files found (X1.txt, X2.txt, etc.)")
            raise FileNotFoundError("Missing key files X1.txt, X2.txt, ...")
        return files

    @staticmethod
    def _normalize_hex(value: str) -> str:
        v = value.strip()
        if v.startswith("0x") or v.startswith("0X"):
            v = v[2:]
        return v.lower()

    def load_targets(self) -> Set[HexKey]:
        """Load target public keys and normalize to plain lowercase hex (no 0x)."""
        if not os.path.exists(self.target_file):
            raise FileNotFoundError(f"Target file not found: {self.target_file}")
        targets: Set[HexKey] = set()
        with open(self.target_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                targets.add(self._normalize_hex(line))
        if not targets:
            logging.warning("Target set is empty after normalization")
        else:
            logging.info(f"Loaded {len(targets)} target public keys from {self.target_file}")
        return targets

    def load_private_keys(self) -> List[List[ParsedKey]]:
        """Load private keys from X*.txt, normalize to int and 64-char hex for output."""
        private_keys: List[List[ParsedKey]] = []
        for filename in self.key_files:
            parsed_file_keys: List[ParsedKey] = []
            with open(filename, 'r') as f:
                for line in f:
                    norm = self._normalize_hex(line)
                    if not norm:
                        continue
                    try:
                        int_val = int(norm, 16)
                        if int_val <= 0 or int_val >= curve.secp256k1.q:
                            # Invalid private key range, skip
                            continue
                        hex_out = norm.rjust(64, '0')
                        parsed_file_keys.append((int_val, hex_out))
                    except ValueError:
                        # Skip non-hex lines silently but you can log at DEBUG if needed
                        continue
            if not parsed_file_keys:
                logging.warning(f"No valid keys found in {filename}")
            else:
                logging.info(f"Loaded {len(parsed_file_keys)} keys from {filename}")
            private_keys.append(parsed_file_keys)
        return private_keys

    @staticmethod
    def _encode_pubkey_hex(total_scalar: int) -> Tuple[HexKey, HexKey]:
        """Return (compressed_hex, uncompressed_hex) of public key from scalar."""
        if total_scalar == 0:
            # 0 * G is point at infinity; skip
            return "", ""
        pub_point = total_scalar * curve.secp256k1.G
        comp = SEC1Encoder.encode_public_key(pub_point, compressed=True).hex()
        uncomp = SEC1Encoder.encode_public_key(pub_point, compressed=False).hex()
        return comp, uncomp

    def _process_batch(self, batch: List[Tuple[ParsedKey, ...]], targets: Set[HexKey]) -> List[Tuple[HexKey, Tuple[HexKey, ...]]]:
        """Process a batch of combinations and return matches as (matched_pub_hex, combo_hexes)."""
        matches: List[Tuple[HexKey, Tuple[HexKey, ...]]] = []
        for combo in batch:
            total = sum(item[0] for item in combo) % curve.secp256k1.q
            comp_hex, uncomp_hex = self._encode_pubkey_hex(total)
            if not comp_hex and not uncomp_hex:
                continue
            if comp_hex in targets:
                matches.append((comp_hex, tuple(item[1] for item in combo)))
            elif uncomp_hex in targets:
                matches.append((uncomp_hex, tuple(item[1] for item in combo)))
        return matches

    def _save_result(self, pub_hex: HexKey, combo_hexes: Tuple[HexKey, ...]) -> None:
        """Append the found match to the output file."""
        with open(self.output_file, 'a') as f:
            f.write("MATCH FOUND:\n")
            f.write(f"Public: 0x{pub_hex}\n")
            for i, key_hex in enumerate(combo_hexes, 1):
                f.write(f"Private {i}: 0x{key_hex}\n")
            f.write("\n")
        self.found_count += 1
        logging.info(f"Match #{self.found_count} found!")

    def _batches(self, private_keys: List[List[ParsedKey]], batch_size: int) -> Iterable[List[Tuple[ParsedKey, ...]]]:
        batch: List[Tuple[ParsedKey, ...]] = []
        for combo in itertools.product(*private_keys):
            batch.append(combo)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    def run_search(self, batch_size: int = 10000, max_workers: int = None) -> bool:
        """Run the search, batching combinations and processing in parallel.

        - Keys and targets are normalized to lowercase hex without 0x prefix
        - Both compressed and uncompressed public key encodings are checked
        - Private keys are pre-parsed to ints for faster scalar math
        """
        if max_workers is None or max_workers <= 0:
            max_workers = os.cpu_count() or 4

        targets = self.load_targets()
        private_keys = self.load_private_keys()

        # Validate that each file has at least one key
        for idx, keys in enumerate(private_keys, start=1):
            if len(keys) == 0:
                raise ValueError(f"File X{idx}.txt contains no valid keys; cannot form combinations")

        # Compute combination count (may be huge; careful with logging)
        total_combinations = 1
        for keys in private_keys:
            total_combinations *= len(keys)

        logging.info(
            f"Starting search with {len(private_keys)} key files; total combinations: {total_combinations}"
        )

        # Parallel processing with multiple in-flight futures
        in_flight_limit = max_workers * 2
        futures = []
        submitted_batches = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for batch in self._batches(private_keys, batch_size=batch_size):
                futures.append(executor.submit(self._process_batch, batch, targets))
                submitted_batches += 1

                if len(futures) >= in_flight_limit:
                    for future in as_completed(futures):
                        matches = future.result()
                        for pub_hex, combo_hexes in matches:
                            self._save_result(pub_hex, combo_hexes)
                    futures.clear()

            # Drain remaining futures
            for future in as_completed(futures):
                matches = future.result()
                for pub_hex, combo_hexes in matches:
                    self._save_result(pub_hex, combo_hexes)

        logging.info(f"Search completed. Found {self.found_count} matches")
        return self.found_count > 0


if __name__ == "__main__":
    print("=== KEY COMBINATION SEARCHER ===")
    try:
        searcher = KeySearcher()
        if searcher.run_search():
            print("\nSUCCESS: Found matching combinations!")
        else:
            print("\nNo matches found.")
    except KeyboardInterrupt:
        print("\nSearch interrupted by user")
    except Exception as e:
        print(f"\nError: {str(e)}")