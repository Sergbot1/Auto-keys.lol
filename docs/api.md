# API Reference

This project ships as runnable scripts. Public entry points are their command-line interfaces. For integrators, the following functions are considered stable within their respective files.

## `CMD_1.4-BTC.py`

- **Function**: `run()`
  - **Description**: Infinite loop that randomly picks a large page number, fetches `https://keys.lol/bitcoin/<pageNum>`, renders the page, extracts numeric values, and if a value is followed by `" btc"` and is greater than zero, appends the value and page URL to `ValidWalletsBTC.txt`. Prints running page count to stdout.
  - **Dependencies**: `requests_html.HTMLSession`, `random`, `re`, `sys`.
  - **Side effects**: Network requests to `keys.lol`; appends to `ValidWalletsBTC.txt` in the working directory; writes progress to stdout.
  - **Usage**: Run the script directly. See examples in `docs/usage.md`.

## `CMD_1.4-ETH.py`

- **Function**: `run()`
  - **Description**: Same logic as BTC variant but targets `https://keys.lol/ethereum/<pageNum>` and logs to `ValidWalletsETH.txt`. Prompts once for `threadCount` (not used in v1.4).
  - **Dependencies**: `requests_html.HTMLSession`, `random`, `re`, `sys`.
  - **Side effects**: Network requests to `keys.lol`; appends to `ValidWalletsETH.txt` in the working directory; writes progress to stdout.
  - **Usage**: Run the script directly. See examples in `docs/usage.md`.

## `tools/find_key_combination.py`

- **Function**: `find_key_combinations(private_keys, target_pubkeys, k, find_all=False, max_combinations_warn=5_000_000)`
  - **Description**: Meet-in-the-middle search for a subset of size exactly `k` from `private_keys` whose modular sum (mod secp256k1 order) corresponds to one of the `target_pubkeys`.
  - **Inputs**:
    - `private_keys` (sequence of ints): Private keys as integers.
    - `target_pubkeys` (sequence of bytes): Compressed public keys (33 bytes each). Utilities inside the module also accept uncompressed hex via CLI and normalize to compressed.
    - `k` (int): Exact subset size to search for.
    - `find_all` (bool): If true, continue searching after the first hit.
    - `max_combinations_warn` (int): Print a warning if the estimated combinations exceed this number.
  - **Returns**: List of tuples `(target_pubkey_bytes, combo_indices)` where `combo_indices` are the indices in `private_keys` that form the solution.
  - **Notes**:
    - Uses only point addition on secp256k1 (via `coincurve`). No discrete logs are computed.
    - Complexity grows combinatorially with `k` and number of keys; keep inputs modest (e.g., `k <= 6`, total keys ~40).
  - **CLI**: See `docs/key-combination.md` for full usage.