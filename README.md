# BIP39 Mnemonic Recovery Tool

Brute-forces the last 2 missing words of a 12-word BIP39 mnemonic and checks balances against a locally synced Liquid (or Bitcoin) node. No API rate limits — scans ~2,600 addresses/second.

## How It Works

A 12-word BIP39 mnemonic = 128 bits of entropy + 4-bit checksum. With 10 known words, there are 2048 × 2048 = 4,194,304 possible combinations for the last 2 words. After checksum filtering, only ~262,144 are valid.

The tool runs in 3 phases:

1. **Phase 1 — Checksum Filter** (CPU, <1s): Filters 4.2M combinations down to ~262K valid mnemonics
2. **Phase 2 — Address Derivation** (CPU, parallel, ~60s): Derives addresses for all valid mnemonics across configurable networks and derivation paths
3. **Phase 3 — Balance Check** (RPC, ~5 min): Scans all derived addresses against a locally synced Elements node using batched `scantxoutset` — no API rate limits

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- ~5 GB disk for Liquid testnet, ~15 GB for Liquid mainnet
- 4 GB RAM minimum
- Works on **Linux**, **macOS**, and **Windows** (via Docker Desktop)

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/liquid-recovery.git
cd liquid-recovery

# 2. Create your config
cp .env.example .env

# 3. Edit .env — set your 10 known words
#    KNOWN_WORDS="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10"

# 4. Run on testnet (to verify everything works)
chmod +x run-local.sh
./run-local.sh

# 5. Run on mainnet (the real deal)
./run-local.sh mainnet
```

## Configuration

Edit `.env` to configure the tool. The only required field is `KNOWN_WORDS`.

| Variable | Default | Description |
|---|---|---|
| `KNOWN_WORDS` | *(required)* | Your 10 known BIP39 words, space-separated, in quotes |
| `NETWORKS` | `liquid` | Networks to scan: `liquid`, `liquid_testnet`, `bitcoin`, `testnet` |
| `ADDRESSES_PER_PATH` | `1` | Number of addresses to derive per derivation path |
| `STOP_ON_FIND` | `true` | Stop after finding the first funded wallet |
| `BIP39_PASSPHRASE` | *(empty)* | Optional BIP39 passphrase (25th word) |
| `NUM_WORKERS` | *(auto)* | CPU workers for derivation (defaults to all cores) |
| `RPC_USER` | `liquid` | Elements node RPC username |
| `RPC_PASS` | `liquid` | Elements node RPC password |

## What Happens When a Match Is Found

The tool prints the result to the terminal:

```
*****************************************************************
  *** WALLET FOUND! ***
  Mnemonic: word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
  Address:  ex1q...
  Network:  liquid
  Path:     m/84'/1776'/0'/0/0
  Balance:  1500000 sats
*****************************************************************
```

Results are also saved to `./output/found_wallets.json`.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Docker Compose                    │
│                                                  │
│  ┌──────────────┐     ┌───────────────────────┐ │
│  │  Elements     │     │  Recovery Worker      │ │
│  │  Node         │◄────│                       │ │
│  │              │ RPC  │  Phase 1: Checksum    │ │
│  │  Syncs Liquid│      │  Phase 2: Derivation  │ │
│  │  blockchain  │      │  Phase 3: RPC Scan    │ │
│  └──────────────┘     └───────────────────────┘ │
│         │                        │               │
│    Docker Volume            ./output/            │
│   (chain data)          (results JSON)           │
└─────────────────────────────────────────────────┘
```

### Supported Networks

| Network | HRP | Coin Type | Derivation Paths |
|---|---|---|---|
| Liquid Mainnet | `ex` | 1776 | `m/84'/1776'/0'/0`, `m/44'/1776'/0'/0`, `m/49'/1776'/0'/0` |
| Liquid Testnet | `tex` | 1 | `m/84'/1'/0'/0`, `m/44'/1'/0'/0`, `m/49'/1'/0'/0` |
| Bitcoin Mainnet | `bc` | 0 | `m/84'/0'/0'/0`, `m/44'/0'/0'/0`, `m/49'/0'/0'/0` |
| Bitcoin Testnet | `tb` | 1 | `m/84'/1'/0'/0`, `m/44'/1'/0'/0` |

### Derivation & Crypto

- **BIP39** seed generation (PBKDF2-HMAC-SHA512, 2048 iterations)
- **BIP32** HD key derivation using [coincurve](https://github.com/ofek/coincurve) (C libsecp256k1 bindings)
- **Bech32** address encoding (BIP173/BIP350)
- **HASH160** (SHA256 + RIPEMD160) with multi-fallback for different OpenSSL builds

## Tips

- **Increase `ADDRESSES_PER_PATH`** if your wallet used many receiving addresses (default scans only the first address per path)
- **Try multiple networks** if unsure which chain has funds: `NETWORKS=liquid,bitcoin`
- **Set `STOP_ON_FIND=false`** to exhaustively check all 262K mnemonics even after finding a match
- **First sync takes time** — Liquid testnet: ~5 min, mainnet: ~10-30 min. Subsequent runs reuse the cached chain data
- **Chain data persists** in a Docker volume (`elements_data`). To reset: `docker volume rm liquid-recovery_elements_data`

## Troubleshooting

**Elements node won't sync:** Check your internet connection and firewall. The node needs outbound access to TCP port 18891 (testnet) or 7042 (mainnet).

**Recovery worker exits immediately:** Check `docker logs recovery-local` for errors. Common issue: `KNOWN_WORDS` not set or contains an invalid BIP39 word.

**No wallets found:** Try increasing `ADDRESSES_PER_PATH` to 20 or 50. Your wallet may have used deeper address indices. Also verify your 10 known words are correct and in the right order.

## License

MIT
