#!/usr/bin/env python3
"""
BIP39 Mnemonic Recovery Tool
=============================
Brute-forces the last 2 missing words of a 12-word BIP39 mnemonic.
Derives addresses for configurable networks and checks balances via API.

Chain-agnostic design: add new networks in NETWORKS config.

Architecture:
  Phase 1 — Checksum filter (CPU, <1s): 4.2M → ~262K valid mnemonics
  Phase 2 — Address derivation (CPU, parallel): derive first address per path
  Phase 3 — API balance check (IO, parallel with backoff): find funded wallets

Usage:
    Set environment variables and run, or use Docker (see README).
"""

import hashlib
import multiprocessing as mp
import os
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict
from threading import Lock

from mnemonic import Mnemonic

from hd_key import HDKey, get_engine
from bech32 import encode as bech32_encode

# ============================================================
# Configuration (all overridable via environment variables)
# ============================================================
NUM_WORKERS = int(os.getenv("NUM_WORKERS", "") or mp.cpu_count())
CHECK_API = os.getenv("CHECK_API", "true").lower() == "true"
ADDRESSES_PER_PATH = int(os.getenv("ADDRESSES_PER_PATH", "5"))
NETWORKS_FILTER = os.getenv("NETWORKS", "liquid")  # comma-separated
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/output")
API_WORKERS = int(os.getenv("API_WORKERS", "8"))
API_RATE_LIMIT = float(os.getenv("API_RATE_LIMIT", "0.1"))  # seconds between calls per thread
RESUME_FROM = int(os.getenv("RESUME_FROM", "0"))  # resume from mnemonic index
PASSPHRASE = os.getenv("BIP39_PASSPHRASE", "")  # optional BIP39 passphrase
BATCH_SAVE_EVERY = int(os.getenv("BATCH_SAVE_EVERY", "500"))
API_KEY = os.getenv("API_KEY", "")  # Blockstream API key (optional, avoids rate limits)
STOP_ON_FIND = os.getenv("STOP_ON_FIND", "true").lower() == "true"

# Multi-worker range splitting: each container handles [RANGE_START, RANGE_END)
WORKER_ID = os.getenv("WORKER_ID", "0")  # identifier for this worker
RANGE_START = int(os.getenv("RANGE_START", "-1"))  # -1 = auto (use full range)
RANGE_END = int(os.getenv("RANGE_END", "-1"))  # -1 = auto (use full range)

# Proxy support: route API calls through HTTP/SOCKS proxy for IP rotation
PROXY_URL = os.getenv("PROXY_URL", "")  # e.g. socks5h://tor:9050 or http://proxy:8080

# Local Elements RPC mode: bypasses API entirely, uses local node
CHECK_MODE = os.getenv("CHECK_MODE", "api")  # "api" or "rpc"
RPC_URL = os.getenv("RPC_URL", "http://localhost:18884")  # Elements RPC endpoint
RPC_USER = os.getenv("RPC_USER", "liquid")
RPC_PASS = os.getenv("RPC_PASS", "liquid")

# ============================================================
# Network definitions (chain-agnostic, extend here)
# ============================================================
NETWORKS = {
    "liquid": {
        "name": "Liquid Network",
        "bech32_hrp": "ex",
        "coin_type": 1776,
        "api_url": "https://blockstream.info/liquid/api/address/{address}",
        "derivation_paths": [
            "m/84'/1776'/0'/0",   # Native SegWit (P2WPKH) — most common
            "m/44'/1776'/0'/0",   # Legacy (P2PKH-style derivation)
            "m/49'/1776'/0'/0",   # Nested SegWit (P2SH-P2WPKH)
        ],
    },
    "bitcoin": {
        "name": "Bitcoin Mainnet",
        "bech32_hrp": "bc",
        "coin_type": 0,
        "api_url": "https://blockstream.info/api/address/{address}",
        "derivation_paths": [
            "m/84'/0'/0'/0",
            "m/44'/0'/0'/0",
            "m/49'/0'/0'/0",
        ],
    },
    "testnet": {
        "name": "Bitcoin Testnet",
        "bech32_hrp": "tb",
        "coin_type": 1,
        "api_url": "https://blockstream.info/testnet/api/address/{address}",
        "derivation_paths": [
            "m/84'/1'/0'/0",
            "m/44'/1'/0'/0",
        ],
    },
    "liquid_testnet": {
        "name": "Liquid Testnet",
        "bech32_hrp": "tex",
        "coin_type": 1,
        "api_url": "https://blockstream.info/liquidtestnet/api/address/{address}",
        "derivation_paths": [
            "m/84'/1'/0'/0",    # Native SegWit (P2WPKH)
            "m/44'/1'/0'/0",    # Legacy
            "m/49'/1'/0'/0",    # Nested SegWit
        ],
    },
}

# ============================================================
# BIP39 utilities
# ============================================================
_WORDLIST: Optional[List[str]] = None


def get_wordlist() -> List[str]:
    global _WORDLIST
    if _WORDLIST is None:
        _WORDLIST = Mnemonic("english").wordlist
    return _WORDLIST


def words_to_110bits(words: List[str]) -> int:
    """Convert 10 known BIP39 words to their 110-bit integer representation."""
    wl = get_wordlist()
    bits = 0
    for w in words:
        bits = (bits << 11) | wl.index(w)
    return bits


def validate_checksum(known_110: int, w11: int, w12: int) -> bool:
    """
    Fast BIP39 checksum validation for a 12-word mnemonic.
    12 words = 132 bits = 128 bits entropy + 4 bits checksum.
    """
    full_132 = (known_110 << 22) | (w11 << 11) | w12
    entropy_bytes = (full_132 >> 4).to_bytes(16, byteorder="big")
    expected_cs = hashlib.sha256(entropy_bytes).digest()[0] >> 4
    return (full_132 & 0xF) == expected_cs


# ============================================================
# Phase 1: Find all checksum-valid mnemonics
# ============================================================
def _worker_find_valid(args: Tuple[int, int, int]) -> List[Tuple[int, int]]:
    """Worker: check a range of word11 indices, all word12 indices."""
    known_110, w11_start, w11_end = args
    results = []
    for w11 in range(w11_start, w11_end):
        for w12 in range(2048):
            if validate_checksum(known_110, w11, w12):
                results.append((w11, w12))
    return results


def find_valid_mnemonics(known_words: List[str], num_workers: int) -> List[str]:
    """Find all checksum-valid 12-word mnemonics given 10 known words."""
    wl = get_wordlist()
    known_110 = words_to_110bits(known_words)

    chunk_size = max(1, 2048 // num_workers)
    chunks = []
    for i in range(0, 2048, chunk_size):
        end = min(i + chunk_size, 2048)
        chunks.append((known_110, i, end))

    print(f"  Dispatching {len(chunks)} chunks across {num_workers} workers...")

    valid_pairs: List[Tuple[int, int]] = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(_worker_find_valid, chunk) for chunk in chunks]
        for f in as_completed(futures):
            valid_pairs.extend(f.result())

    valid_pairs.sort()

    mnemonics = []
    for w11, w12 in valid_pairs:
        words_12 = known_words + [wl[w11], wl[w12]]
        mnemonics.append(" ".join(words_12))

    return mnemonics


# ============================================================
# Phase 2: Derive addresses (CPU-only, no network)
# ============================================================
def _ripemd160(data: bytes) -> bytes:
    """RIPEMD160 with multiple fallbacks for different environments."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        pass
    try:
        return hashlib.new("ripemd160", data, usedforsecurity=False).digest()
    except (ValueError, TypeError):
        pass
    from Crypto.Hash import RIPEMD160
    return RIPEMD160.new(data).digest()


def hash160(data: bytes) -> bytes:
    return _ripemd160(hashlib.sha256(data).digest())


def derive_addresses_for_mnemonic(
    mnemonic_str: str,
    networks: Dict,
    addr_count: int,
    passphrase: str = "",
) -> List[Dict]:
    """Derive addresses for one mnemonic across networks/paths. Pure CPU."""
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic_str.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
    )
    root = HDKey.from_seed(seed)

    addresses = []
    for net_name, net_cfg in networks.items():
        hrp = net_cfg["bech32_hrp"]
        for path_base in net_cfg["derivation_paths"]:
            try:
                account = root.derive_path(path_base)
            except Exception:
                continue
            for i in range(addr_count):
                child = account.derive_child(i)
                addr = bech32_encode(hrp, 0, list(hash160(child.pubkey)))
                addresses.append(
                    {
                        "network": net_name,
                        "path": f"{path_base}/{i}",
                        "address": addr,
                    }
                )
    return addresses


def _worker_derive_batch(args):
    """Worker: derive addresses for a batch of mnemonics."""
    batch, networks, addr_count, passphrase = args
    results = []
    for idx, mnemonic_str in batch:
        addrs = derive_addresses_for_mnemonic(mnemonic_str, networks, addr_count, passphrase)
        results.append((idx, mnemonic_str, addrs))
    return results


def derive_all_addresses(
    mnemonics: List[str],
    networks: Dict,
    addr_count: int,
    passphrase: str,
    num_workers: int,
    start_idx: int = 0,
) -> List[Tuple[int, str, List[Dict]]]:
    """
    Phase 2: Derive addresses for all mnemonics using multiprocessing.
    Returns list of (index, mnemonic, addresses).
    """
    indexed = list(enumerate(mnemonics))[start_idx:]
    total = len(indexed)

    # Split into batches for workers
    batch_size = max(1, total // (num_workers * 4))
    batches = []
    for i in range(0, total, batch_size):
        batch = indexed[i : i + batch_size]
        batches.append((batch, networks, addr_count, passphrase))

    all_results = []
    completed = 0

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = {executor.submit(_worker_derive_batch, b): b for b in batches}
        for fut in as_completed(futures):
            batch_results = fut.result()
            all_results.extend(batch_results)
            completed += len(batch_results)
            pct = 100 * completed / total
            print(
                f"  Deriving: {completed}/{total} ({pct:.1f}%)",
                end="\r",
                flush=True,
            )

    print(f"  Deriving: {total}/{total} (100.0%) — done")
    all_results.sort(key=lambda x: x[0])
    return all_results


# ============================================================
# Phase 3: Check addresses against blockchain API
# ============================================================
_rate_limit_lock = Lock()
_backoff_until = 0.0


def _get_session() -> "requests.Session":
    """Get a thread-local requests session with proxy if configured."""
    import requests
    import threading
    _tls = threading.local()
    if not hasattr(_tls, "session"):
        _tls.session = requests.Session()
        if PROXY_URL:
            _tls.session.proxies = {
                "http": PROXY_URL,
                "https": PROXY_URL,
            }
    return _tls.session


def wait_for_proxy(timeout: int = 120, interval: int = 5):
    """Wait for the SOCKS/HTTP proxy to become reachable before making API calls."""
    if not PROXY_URL:
        return
    import requests
    print(f"  Waiting for proxy ({PROXY_URL}) to be ready...", flush=True)
    deadline = time.time() + timeout
    session = requests.Session()
    session.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    test_url = "https://blockstream.info/api/blocks/tip/height"
    while time.time() < deadline:
        try:
            resp = session.get(test_url, timeout=10)
            if resp.status_code == 200:
                print(f"  ✓ Proxy is ready (got block height: {resp.text.strip()})", flush=True)
                session.close()
                return
        except Exception:
            pass
        remaining = int(deadline - time.time())
        print(f"  Proxy not ready yet, retrying in {interval}s ({remaining}s left)...", flush=True)
        time.sleep(interval)
    session.close()
    print(f"  ⚠ Proxy not reachable after {timeout}s — proceeding anyway (may fail)", flush=True)


# ============================================================
# RPC helpers (local Elements node)
# ============================================================
def _rpc_call(method: str, params: list = None) -> dict:
    """Make a JSON-RPC call to the local Elements node."""
    import requests
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }
    resp = requests.post(
        RPC_URL,
        json=payload,
        auth=(RPC_USER, RPC_PASS),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result")


def wait_for_node(timeout: int = 600, interval: int = 10):
    """Wait for the Elements node to be synced and ready."""
    print(f"  Waiting for Elements node ({RPC_URL}) to sync...", flush=True)
    deadline = time.time() + timeout
    last_progress = -1
    while time.time() < deadline:
        try:
            info = _rpc_call("getblockchaininfo")
            progress = info.get("verificationprogress", 0)
            headers = info.get("headers", 0)
            blocks = info.get("blocks", 0)
            pct = progress * 100

            if pct != last_progress:
                print(
                    f"  Sync: {pct:.1f}% ({blocks}/{headers} blocks)",
                    flush=True,
                )
                last_progress = pct

            if progress > 0.999:
                print(f"  ✓ Node synced! ({blocks} blocks)", flush=True)
                return
        except Exception as e:
            remaining = int(deadline - time.time())
            print(
                f"  Node not ready ({type(e).__name__}), retrying in {interval}s ({remaining}s left)...",
                flush=True,
            )
        time.sleep(interval)
    print(f"  ⚠ Node not fully synced after {timeout}s — proceeding anyway", flush=True)


def check_addresses_batch_rpc(
    derived_data: List[Tuple[int, str, List[Dict]]],
    output_dir: str,
    stop_on_find: bool,
    batch_size: int = 500,
) -> List[Dict]:
    """
    Phase 3 (RPC mode): Check all derived addresses against local Elements node.

    Uses BATCHED scantxoutset — passes up to batch_size addresses per RPC call.
    scantxoutset accepts multiple descriptors: ["addr(a1)", "addr(a2)", ...]
    This is orders of magnitude faster than one-address-at-a-time.
    """
    found_wallets = []
    t0 = time.time()

    # Build flat list: (mnemonic_str, addr_info)
    work_items = []
    for idx, mnemonic_str, addr_list in derived_data:
        for addr_info in addr_list:
            work_items.append((mnemonic_str, addr_info))

    total_lookups = len(work_items)
    lookups_done = 0

    print(f"  Scanning {total_lookups:,} addresses in batches of {batch_size}...", flush=True)

    # Process in batches
    for batch_start in range(0, total_lookups, batch_size):
        batch = work_items[batch_start : batch_start + batch_size]

        # Build descriptor list for this batch
        descriptors = [f"addr({item[1]['address']})" for item in batch]
        batch_num = batch_start // batch_size + 1
        total_batches = (total_lookups + batch_size - 1) // batch_size

        # Log each batch with sample addresses
        first_addr = batch[0][1]['address']
        last_addr = batch[-1][1]['address']
        print(
            f"  [Batch {batch_num}/{total_batches}] Scanning {len(batch)} addresses: "
            f"{first_addr[:16]}... → {last_addr[:16]}...",
            flush=True,
        )

        try:
            t_batch = time.time()
            result = _rpc_call("scantxoutset", ["start", descriptors])
            batch_elapsed = time.time() - t_batch
            print(
                f"    ✓ Batch {batch_num} done in {batch_elapsed:.1f}s — "
                f"unspents: {len(result.get('unspents', [])) if result else 0}",
                flush=True,
            )
        except Exception as e:
            print(f"    ⚠ RPC error on batch {batch_num}: {e}", flush=True)
            lookups_done += len(batch)
            continue

        lookups_done += len(batch)

        # Check if any unspents were found
        if result and result.get("unspents"):
            # Map found addresses back to their mnemonics
            funded_addrs = {}
            for utxo in result["unspents"]:
                addr = ""
                # Elements returns scriptPubKey as hex string; Bitcoin Core as dict
                spk = utxo.get("scriptPubKey", "")
                if isinstance(spk, dict):
                    addr = spk.get("address", "")
                # Fall back to descriptor field: "addr(tex1q...)#checksum"
                if not addr:
                    desc = utxo.get("desc", "")
                    if "addr(" in desc:
                        addr = desc.split("addr(")[1].split(")")[0]
                amt = utxo.get("amount", 0)
                if addr:
                    if addr not in funded_addrs:
                        funded_addrs[addr] = 0
                    funded_addrs[addr] += amt

            for mnemonic_str, addr_info in batch:
                if addr_info["address"] in funded_addrs:
                    balance_btc = funded_addrs[addr_info["address"]]
                    balance_sats = int(round(balance_btc * 1e8))
                    hit = {
                        "mnemonic": mnemonic_str,
                        "address": addr_info["address"],
                        "network": addr_info["network"],
                        "path": addr_info["path"],
                        "funded_total": balance_sats,
                        "spent_total": 0,
                        "balance": balance_sats,
                    }
                    found_wallets.append(hit)
                    print(f"\n{'*' * 65}", flush=True)
                    print(f"  *** WALLET FOUND! ***", flush=True)
                    print(f"  Mnemonic: {hit['mnemonic']}", flush=True)
                    print(f"  Address:  {hit['address']}", flush=True)
                    print(f"  Network:  {hit['network']}", flush=True)
                    print(f"  Path:     {hit['path']}", flush=True)
                    print(f"  Balance:  {hit['balance']} sats", flush=True)
                    print(f"{'*' * 65}\n", flush=True)

                    # Save immediately
                    results_file = os.path.join(output_dir, "found_wallets.json")
                    with open(results_file, "w") as f:
                        json.dump(found_wallets, f, indent=2)

                    if stop_on_find:
                        return found_wallets

        # Progress (use \n so it shows in docker logs)
        elapsed = time.time() - t0
        rate = lookups_done / elapsed if elapsed > 0 else 0
        remaining = total_lookups - lookups_done
        eta_s = remaining / rate if rate > 0 else 0
        pct = 100 * lookups_done / total_lookups
        print(
            f"  RPC: {lookups_done:,}/{total_lookups:,} ({pct:.1f}%) | "
            f"{rate:.0f} addr/s | "
            f"ETA: {eta_s:.0f}s | "
            f"Found: {len(found_wallets)}",
            flush=True,
        )

    return found_wallets


def check_address(address: str, api_url_template: str, api_key: str = "") -> Optional[Dict]:
    """Check a single address for balance via API with backoff and proxy support."""
    global _backoff_until
    import requests

    # Respect global backoff
    now = time.time()
    if now < _backoff_until:
        time.sleep(_backoff_until - now)

    url = api_url_template.format(address=address)
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    session = _get_session()

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = session.get(url, timeout=15, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                chain = data.get("chain_stats", {})
                mempool = data.get("mempool_stats", {})
                funded = chain.get("funded_txo_sum", 0) + mempool.get("funded_txo_sum", 0)
                spent = chain.get("spent_txo_sum", 0) + mempool.get("spent_txo_sum", 0)
                if funded > 0:
                    return {
                        "funded_total": funded,
                        "spent_total": spent,
                        "balance": funded - spent,
                        "tx_count": chain.get("tx_count", 0) + mempool.get("tx_count", 0),
                    }
                return None  # Address exists but no funds
            elif resp.status_code == 429:
                # Rate limited — exponential backoff
                wait = min(60, (2 ** attempt) * 5)
                with _rate_limit_lock:
                    _backoff_until = max(_backoff_until, time.time() + wait)
                print(f"\n  ⚠ Rate limited, backing off {wait}s...", flush=True)
                time.sleep(wait)
            else:
                return None
        except requests.exceptions.Timeout:
            time.sleep(2)
        except Exception:
            return None
    return None


def check_addresses_batch(
    derived_data: List[Tuple[int, str, List[Dict]]],
    networks: Dict,
    api_workers: int,
    rate_limit: float,
    api_key: str,
    output_dir: str,
    stop_on_find: bool,
) -> List[Dict]:
    """
    Phase 3: Check all derived addresses against APIs.
    Uses thread pool for IO-bound API calls.
    """
    found_wallets = []
    total = len(derived_data)
    checked = 0
    t0 = time.time()
    stop_flag = False

    # Build flat list of (mnemonic, addr_info) for thread pool
    work_items = []
    for idx, mnemonic_str, addr_list in derived_data:
        for addr_info in addr_list:
            work_items.append((idx, mnemonic_str, addr_info))

    total_lookups = len(work_items)
    lookup_done = 0

    def _check_one(item):
        nonlocal lookup_done
        idx, mnemonic_str, addr_info = item
        net_name = addr_info["network"]
        api_url = networks[net_name]["api_url"]
        result = check_address(addr_info["address"], api_url, api_key)
        if rate_limit > 0:
            time.sleep(rate_limit)
        lookup_done += 1
        if result:
            return {
                "mnemonic": mnemonic_str,
                "address": addr_info["address"],
                "network": net_name,
                "path": addr_info["path"],
                **result,
            }
        return None

    with ThreadPoolExecutor(max_workers=api_workers) as pool:
        futures = {pool.submit(_check_one, item): item for item in work_items}

        for fut in as_completed(futures):
            if stop_flag:
                break

            result = fut.result()
            if result:
                found_wallets.append(result)
                print(f"\n{'*' * 65}")
                print(f"  *** WALLET FOUND! ***")
                print(f"  Mnemonic: {result['mnemonic']}")
                print(f"  Address:  {result['address']}")
                print(f"  Network:  {result['network']}")
                print(f"  Path:     {result['path']}")
                print(f"  Balance:  {result['balance']} sats")
                print(f"  Funded:   {result['funded_total']} sats")
                print(f"{'*' * 65}\n")

                # Save immediately
                results_file = os.path.join(output_dir, "found_wallets.json")
                with open(results_file, "w") as f:
                    json.dump(found_wallets, f, indent=2)

                if stop_on_find:
                    stop_flag = True
                    # Cancel pending futures
                    for pending_fut in futures:
                        pending_fut.cancel()

            # Progress
            elapsed = time.time() - t0
            rate = lookup_done / elapsed if elapsed > 0 else 0
            remaining_lookups = total_lookups - lookup_done
            eta_s = remaining_lookups / rate if rate > 0 else 0

            if lookup_done % 50 == 0:
                print(
                    f"  API: {lookup_done}/{total_lookups} lookups | "
                    f"{rate:.1f}/s | "
                    f"ETA: {eta_s / 60:.0f}m | "
                    f"Found: {len(found_wallets)}",
                    end="\r",
                    flush=True,
                )

    return found_wallets


# ============================================================
# Progress and output
# ============================================================
def save_progress(output_dir: str, data: dict, filename: str = "progress.json"):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def print_banner(known_words, num_workers, networks, check_api, addr_count, range_info=""):
    print("=" * 65)
    print("  BIP39 MNEMONIC RECOVERY TOOL")
    print(f"  Last 2 Words Brute-Force — Worker {WORKER_ID}")
    print("=" * 65)
    print(f"  Known words (1-10): {' '.join(known_words)}")
    print(f"  Missing:            words 11 and 12")
    print(f"  Search space:       2048 × 2048 = 4,194,304 combinations")
    print(f"  Expected valid:     ~262,144 (after checksum filter)")
    print(f"  Workers (CPU):      {num_workers}")
    print(f"  Workers (API):      {API_WORKERS}")
    print(f"  Crypto engine:      {get_engine()}")
    print(f"  Networks:           {', '.join(networks.keys())}")
    print(f"  Addresses/path:     {addr_count}")
    print(f"  API checking:       {'ENABLED' if check_api else 'DISABLED'}")
    print(f"  Check mode:         {CHECK_MODE.upper()} {'(' + RPC_URL + ')' if CHECK_MODE == 'rpc' else ''}")
    if CHECK_MODE == "api":
        print(f"  API key:            {'SET' if API_KEY else 'not set (rate limits apply)'}")
        print(f"  Proxy:              {PROXY_URL if PROXY_URL else 'direct (no proxy)'}")
    print(f"  Stop on first find: {'yes' if STOP_ON_FIND else 'no'}")
    if range_info:
        print(f"  Range:              {range_info}")
    if PASSPHRASE:
        print(f"  BIP39 passphrase:   (set)")
    print("=" * 65)


# ============================================================
# Main
# ============================================================
def main():
    # --- Parse inputs ---
    known_words_str = os.getenv("KNOWN_WORDS", "").strip()
    if not known_words_str:
        print("\nERROR: KNOWN_WORDS environment variable not set.")
        print("Set it to your 10 known words, space-separated.")
        print('Example: KNOWN_WORDS="abandon ability able about above absent absorb abstract absurd abuse"')
        sys.exit(1)

    known_words = known_words_str.lower().split()
    if len(known_words) != 10:
        print(f"\nERROR: Expected 10 words, got {len(known_words)}.")
        sys.exit(1)

    wl = get_wordlist()
    for w in known_words:
        if w not in wl:
            print(f"\nERROR: '{w}' is not a valid BIP39 word.")
            from difflib import get_close_matches
            matches = get_close_matches(w, wl, n=5, cutoff=0.6)
            if matches:
                print(f"  Did you mean: {', '.join(matches)}?")
            sys.exit(1)

    # Filter active networks
    active_filter = set(NETWORKS_FILTER.split(","))
    active_networks = {k: v for k, v in NETWORKS.items() if k in active_filter}
    if not active_networks:
        print(f"\nERROR: No valid networks in NETWORKS='{NETWORKS_FILTER}'")
        print(f"  Available: {', '.join(NETWORKS.keys())}")
        sys.exit(1)

    # ==== Phase 1: Checksum brute-force ====
    print(f"\n{'─' * 65}")
    print("[PHASE 1] Brute-forcing checksum-valid mnemonics...")
    print(f"{'─' * 65}")
    t0 = time.time()
    valid_mnemonics = find_valid_mnemonics(known_words, NUM_WORKERS)
    t1 = time.time()
    print(f"\n  ✓ Found {len(valid_mnemonics)} valid mnemonics in {t1 - t0:.2f}s")

    # Apply range slicing for multi-worker mode
    total_valid = len(valid_mnemonics)
    r_start = RANGE_START if RANGE_START >= 0 else 0
    r_end = RANGE_END if RANGE_END >= 0 else total_valid
    r_start = min(r_start, total_valid)
    r_end = min(r_end, total_valid)

    if r_start > 0 or r_end < total_valid:
        range_info = f"[{r_start}..{r_end}) of {total_valid} ({r_end - r_start} mnemonics)"
        valid_mnemonics = valid_mnemonics[r_start:r_end]
        print(f"  ✓ Range slice: {range_info}")
    else:
        range_info = f"full range (0..{total_valid})"

    print_banner(known_words, NUM_WORKERS, active_networks, CHECK_API, ADDRESSES_PER_PATH, range_info)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    mnemonics_file = os.path.join(OUTPUT_DIR, f"valid_mnemonics_w{WORKER_ID}.txt")
    with open(mnemonics_file, "w") as f:
        for m in valid_mnemonics:
            f.write(m + "\n")
    print(f"  ✓ Saved to {mnemonics_file}")

    if not CHECK_API:
        print(f"\n  API checking disabled. Re-run with CHECK_API=true to scan balances.")
        print(f"  Total valid mnemonics in range: {len(valid_mnemonics)}")
        return

    # ==== Phase 2: Derive addresses (CPU-only) ====
    print(f"\n{'─' * 65}")
    print(f"[PHASE 2] Worker {WORKER_ID}: Deriving addresses (offline, CPU-only)...")
    print(f"{'─' * 65}")
    total_paths = sum(len(n["derivation_paths"]) for n in active_networks.values())
    addrs_per_mnemonic = total_paths * ADDRESSES_PER_PATH
    print(f"  Mnemonics in range: {len(valid_mnemonics)}")
    print(f"  Addresses per mnemonic: {addrs_per_mnemonic} ({total_paths} paths × {ADDRESSES_PER_PATH} addrs)")
    print(f"  Total addresses to derive: {len(valid_mnemonics) * addrs_per_mnemonic:,}")
    print()

    t2 = time.time()
    derived = derive_all_addresses(
        valid_mnemonics, active_networks, ADDRESSES_PER_PATH,
        PASSPHRASE, NUM_WORKERS, RESUME_FROM,
    )
    t3 = time.time()
    print(f"  ✓ Derived addresses in {t3 - t2:.1f}s ({len(derived) * addrs_per_mnemonic:,} total)")

    # Save derived address map
    addr_map_file = os.path.join(OUTPUT_DIR, f"address_map_w{WORKER_ID}.jsonl")
    with open(addr_map_file, "w") as f:
        for idx, mnemonic_str, addrs in derived:
            f.write(json.dumps({
                "index": idx,
                "mnemonic": mnemonic_str,
                "addresses": [a["address"] for a in addrs],
            }) + "\n")
    print(f"  ✓ Address map saved to {addr_map_file}")

    # ==== Phase 3: Balance checking ====
    total_lookups = len(derived) * addrs_per_mnemonic

    if CHECK_MODE == "rpc":
        # ---- RPC mode: local Elements node (no rate limits) ----
        print(f"\n{'─' * 65}")
        print(f"[PHASE 3] Worker {WORKER_ID}: Checking addresses via LOCAL RPC node...")
        print(f"{'─' * 65}")
        print(f"  Mode:          Local Elements RPC ({RPC_URL})")
        print(f"  Total lookups: {total_lookups:,}")
        print(f"  Threads:       {API_WORKERS}")
        print(f"  Rate limits:   NONE")
        print()

        wait_for_node()

        found = check_addresses_batch_rpc(
            derived, OUTPUT_DIR, STOP_ON_FIND,
        )
    else:
        # ---- API mode: Blockstream Esplora API ----
        print(f"\n{'─' * 65}")
        print(f"[PHASE 3] Worker {WORKER_ID}: Checking addresses against blockchain API...")
        print(f"{'─' * 65}")

        # Wait for proxy (Tor) to be fully bootstrapped before making API calls
        wait_for_proxy()
        effective_rate = API_WORKERS / max(API_RATE_LIMIT, 0.01)
        est_seconds = total_lookups / effective_rate
        print(f"  Total API lookups: {total_lookups:,}")
        print(f"  Effective rate: ~{effective_rate:.0f} req/s ({API_WORKERS} threads, {API_RATE_LIMIT}s delay)")
        print(f"  Estimated time: ~{est_seconds / 3600:.1f} hours")
        if not API_KEY:
            print(f"  ⚠ No API key set. Free tier: 700 req/hour.")
            print(f"    Get a key at: https://dashboard.blockstream.info")
            print(f"    Set via: API_KEY=your_key_here")
        print()

        found = check_addresses_batch(
            derived, active_networks, API_WORKERS,
            API_RATE_LIMIT, API_KEY, OUTPUT_DIR, STOP_ON_FIND,
        )

    # ==== Summary ====
    total_time = time.time() - t0
    print(f"\n\n{'=' * 65}")
    print(f"  RECOVERY COMPLETE")
    print(f"{'=' * 65}")
    print(f"  Total time:        {total_time:.1f}s ({total_time / 60:.1f}m)")
    print(f"  Mnemonics checked: {len(derived)}")
    print(f"  API lookups:       {total_lookups:,}")
    print(f"  Wallets found:     {len(found)}")

    if found:
        results_file = os.path.join(OUTPUT_DIR, "found_wallets.json")
        with open(results_file, "w") as f:
            json.dump(found, f, indent=2)
        print(f"  Results saved to:  {results_file}")
        print(f"\n  YOUR RECOVERED MNEMONIC(S):")
        seen = set()
        for hit in found:
            if hit["mnemonic"] not in seen:
                seen.add(hit["mnemonic"])
                print(f"    → {hit['mnemonic']}")
    else:
        print(f"\n  No wallets with balance found.")
        print(f"  Suggestions:")
        print(f"    1. Try with more addresses: ADDRESSES_PER_PATH=50")
        print(f"    2. Try additional networks: NETWORKS=liquid,bitcoin")
        print(f"    3. Verify the 10 known words are correct")
        print(f"    4. If using a BIP39 passphrase, set BIP39_PASSPHRASE")
        print(f"    5. Get a Blockstream API key to avoid rate limits")

    # Save final progress
    save_progress(OUTPUT_DIR, {
        "status": "completed",
        "total_mnemonics": len(valid_mnemonics),
        "checked": len(derived),
        "found": len(found),
        "total_time_seconds": total_time,
    })

    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()
