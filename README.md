# entropix

> **Payload Entropy Analyzer & XOR Transform Engine**  
> Profile Shannon entropy across shellcode and blobs, visualize hot zones, and find XOR keys that bring your payload below EDR detection thresholds.

```
                _                    _
  ___ _ _  __ _| |_ _ _ ___  _ __ (_)_  __
 / -_) ' \/ _` |  _| '_/ _ \| '_ \| \ \/ /
 \___|_||_\__, |\__|_| \___/| .__/|_|/_\_\
          |___/             |_|
  v0.1 | Payload Entropy Analyzer | artais.io
```

---

## The Problem

High entropy is one of the oldest and most reliable EDR heuristics. Legitimate executables have entropy in the `5.0–6.5` range — compiled code, string tables, resource sections. Payloads don't. XOR-encrypted shellcode, packed PE loaders, and obfuscated blobs routinely land at `7.2+`, which puts them squarely in the alert zone for tools like Defender, CrowdStrike, and Carbon Black before a single API call is made.

Before you worry about string signatures, you need to know: **what is your payload's entropy, and where are the hot zones?**

`entropix` answers that, then helps you do something about it.

---

## Installation

```bash
git clone https://github.com/Artais-Security/entropix
cd entropix
pip install -r requirements.txt
```

`rich` is the only dependency and is optional — the tool falls back to plain output automatically.

---

## Usage

```
usage: entropix [-h] [--block-size N] [--window N] [--xor] [--key-len N]
                [--top N] [--format {rich,plain,json}]
                target

positional arguments:
  target                Shellcode blob or binary to analyze

options:
  --block-size N, -b N  Block size for per-region entropy (default: 256)
  --window N, -w N      Sliding window size for heatmap (default: 64)
  --xor, -x             Run XOR key analysis
  --key-len N, -k N     XOR key length in bytes to evaluate (default: 4)
  --top N, -n N         Top key candidates to show (default: 10)
  --format {rich,plain,json}, -f
                        Output format (default: rich)
```

### Examples

**Profile a blob before staging:**
```bash
python entropix.py beacon.bin
```

**Find XOR keys that reduce entropy with 4-byte keys:**
```bash
python entropix.py shellcode.bin --xor --key-len 4
```

**Try longer keys, show top 20 candidates:**
```bash
python entropix.py implant.bin --xor --key-len 8 --top 20
```

**Finer block granularity to isolate hot regions:**
```bash
python entropix.py payload.bin --block-size 64 --window 16
```

**JSON output for toolchain integration:**
```bash
python entropix.py payload.bin --xor --format json | tee entropy_report.json
```

---

## Output Breakdown

### Entropy Score

```
Entropy  : 7.5193 bits/byte  [CRITICAL]
Chi²     : 311.00

Thresholds:
  6.5  → ELEVATED  (watchlist range)
  7.0  → HIGH      (common EDR alert threshold)
  7.2  → CRITICAL  (most EDRs flag this range)
```

The Chi-square statistic measures how far your byte distribution deviates from random. Counter-intuitively, *lower* chi-square means *more uniform* distribution — which is another detection signal on its own. Truly encrypted payloads score low on chi-square *and* high on entropy. Both numbers matter.

### Entropy Heatmap

```
Low entropy ← ──────────────────── → High entropy
  [                    ░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒]
```

Single-row visual of entropy across the file from start (left) to end (right). Blank = low entropy, `█` = near-maximum. Mixed payloads with a plaintext header and encrypted body show the transition clearly.

### Block Breakdown

```
Offset       Size     Entropy    Status
0x0          256      0.0000     OK
0x100        256      7.2689     CRITICAL ◄
0x200        256      5.0000     OK
```

Per-block entropy with flagged regions. Use `--block-size` to tune granularity. Smaller blocks isolate hot zones more precisely at the cost of statistical reliability on small samples.

### XOR Key Analysis

```
Rank   Key (hex)     Key Entropy   Result Entropy   Delta      < 6.5?
1      41414141      0.0           5.9821           1.5372     ✓
2      42424242      0.0           5.9834           1.5339     ✓
...
```

Evaluates hundreds of candidate XOR keys and ranks by resulting entropy. Key candidates include:
- **Single-byte repeating** (`0x41414141`) — zero key entropy, maximum simplicity
- **Two-byte alternating** (`0x41424142`) — slightly higher variance, sometimes more effective on patterned payloads
- **Printable ASCII sequences** — useful when key material needs to blend in

---

## Understanding the Math

### Why XOR can (and can't) reduce entropy

XOR with a low-entropy key works by introducing a pattern into otherwise random data. A truly random payload — like output from `/dev/urandom` or a strong cipher — has near-maximum entropy by design, and a simple XOR key cannot change that in any meaningful way. If `entropix` reports that no key brings your payload below threshold, that's not a bug — it's telling you the truth: **your payload is already maximally random, and XOR obfuscation won't help here**.

What XOR *does* help with: payloads that have high entropy due to compression or simple encoding rather than true randomness, or payloads with structural regularity that a cycling key can partially mask.

### Effective entropy reduction strategies

| Scenario | Approach |
|---|---|
| Payload > 7.2, truly random | Re-encode with a scheme that introduces controlled structure (e.g., nibble expansion, word-substitution encoding) |
| Payload 6.5–7.2, patterned | XOR with a low-entropy key — often sufficient |
| Payload < 6.5 | Strings are the bigger risk — run `sigdodge` instead |
| PE binary with high-entropy section | Target the specific section rather than the whole file |

---

## Integration

### Pipeline: track entropy across patching iterations

```bash
# baseline
python entropix.py implant.bin --format json > before.json

# apply transforms
# ... patch, re-encode, etc.

# compare
python entropix.py implant_patched.bin --format json > after.json
python3 -c "
import json
b = json.load(open('before.json'))
a = json.load(open('after.json'))
print(f'Before: {b[\"entropy\"]:.4f} ({b[\"label\"]})')
print(f'After:  {a[\"entropy\"]:.4f} ({a[\"label\"]})')
print(f'Delta:  {b[\"entropy\"] - a[\"entropy\"]:+.4f}')
"
```

### Pair with sigdodge

`entropix` and [`sigdodge`](https://github.com/Artais-Security/sigdodge) are complementary tools covering the two main pre-detonation detection vectors:

```
entropix  → entropy-based heuristics (are you too random?)
sigdodge  → string/pattern signatures (are you too recognizable?)
```

Run both before staging.

---

## Limitations

- Analysis is static. In-memory entropy at runtime may differ significantly from on-disk.
- Small files (<256 bytes) produce less statistically reliable entropy scores.
- XOR key search is exhaustive over a curated candidate set, not cryptographically optimal. For serious entropy reduction on high-entropy payloads, consider structural re-encoding approaches beyond simple XOR.

---

## License

MIT — do what you want, attribution appreciated.

---

*Built by [Artais Security](https://artais.io) — offensive security consulting.*  
*"The best defense is a good offense."*
