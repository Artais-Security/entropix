#!/usr/bin/env python3
"""
entropix - Payload Entropy Analyzer & XOR Transform Engine
Profiles Shannon entropy across shellcode/blobs, visualizes hot zones,
and applies XOR cycling to reduce entropy below EDR detection thresholds.

Author: Artais Security (artais.io)
License: MIT
"""

import os
import sys
import math
import json
import struct
import random
import hashlib
import argparse
import itertools
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

BANNER = r"""
                _                    _
  ___ _ _  __ _| |_ _ _ ___  _ __ (_)_  __
 / -_) ' \/ _` |  _| '_/ _ \| '_ \| \ \/ /
 \___|_||_\__, |\__|_| \___/| .__/|_|/_\_\
          |___/             |_|
  v0.1 | Payload Entropy Analyzer | artais.io
"""

# EDR entropy threshold heuristics (industry-observed)
THRESHOLD_WARN  = 6.5   # elevated — investigate
THRESHOLD_HIGH  = 7.0   # high — common EDR alert threshold
THRESHOLD_CRIT  = 7.2   # critical — most EDRs flag this range

BLOCK_SIZE_DEFAULT = 256   # bytes per analysis block
WINDOW_SIZE_DEFAULT = 64   # sliding window size for heatmap

# Gradient characters for ASCII heatmap (low → high entropy)
HEATMAP_CHARS = " ░▒▓█"

# ---------------------------------------------------------------------------
# Core math
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def byte_distribution(data: bytes) -> list[int]:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def chi_square(data: bytes) -> float:
    """Chi-square statistic vs. uniform distribution. Lower = more uniform."""
    if not data:
        return 0.0
    n = len(data)
    expected = n / 256.0
    counts = byte_distribution(data)
    return sum((c - expected) ** 2 / expected for c in counts)


def sliding_entropy(data: bytes, window: int) -> list[float]:
    """Compute entropy for each sliding window position."""
    if len(data) < window:
        return [shannon_entropy(data)]
    return [
        shannon_entropy(data[i:i + window])
        for i in range(0, len(data) - window + 1, window // 2)
    ]


def block_entropy(data: bytes, block_size: int) -> list[tuple[int, int, float]]:
    """Return (offset, size, entropy) for each block."""
    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        blocks.append((i, len(chunk), shannon_entropy(chunk)))
    return blocks


# ---------------------------------------------------------------------------
# XOR transform
# ---------------------------------------------------------------------------

def xor_cycle(data: bytes, key: bytes) -> bytes:
    """XOR data with a cycling key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def key_entropy(key: bytes) -> float:
    return shannon_entropy(key)


def generate_low_entropy_keys(key_len: int, count: int = 64) -> list[bytes]:
    """
    Generate candidate XOR keys biased toward low entropy.
    Strategies:
      - Single repeating byte
      - Two-byte alternating pattern
      - Printable ASCII sequences (low byte variance)
      - Sparse patterns (mostly one byte with occasional variation)
    """
    candidates: list[bytes] = []

    # Single-byte keys (lowest possible entropy)
    for b in range(1, 256):  # skip 0x00 (null-xor is identity)
        candidates.append(bytes([b] * key_len))

    # Two-byte alternating — slightly higher variance but often effective
    for b1 in range(0x20, 0x7F):
        for b2 in range(0x20, 0x7F):
            if b1 != b2:
                pattern = bytes([(b1 if i % 2 == 0 else b2) for i in range(key_len)])
                candidates.append(pattern)
            if len(candidates) > 512:
                break
        if len(candidates) > 512:
            break

    # Printable ASCII block keys
    for start in range(0x41, 0x5B):  # A-Z range
        candidates.append(bytes([(start + i) % 0x7E or 0x20 for i in range(key_len)]))

    return candidates[:count + 255]  # trim, keeping all single-byte ones


def find_best_xor_keys(
    data: bytes,
    key_len: int = 4,
    top_n: int = 10,
    target: float = THRESHOLD_WARN,
) -> list[dict]:
    """
    Evaluate candidate XOR keys and rank by resulting entropy.
    Returns top_n results that bring entropy closest to / below target.
    """
    candidates = generate_low_entropy_keys(key_len)
    results = []

    original_ent = shannon_entropy(data)

    for key in candidates:
        transformed = xor_cycle(data, key)
        ent = shannon_entropy(transformed)
        delta = original_ent - ent
        results.append({
            "key": key,
            "key_hex": key.hex(),
            "key_entropy": round(key_entropy(key), 4),
            "result_entropy": round(ent, 4),
            "delta": round(delta, 4),
            "below_target": ent < target,
        })

    # Sort: below-target first, then by lowest resulting entropy
    results.sort(key=lambda r: (not r["below_target"], r["result_entropy"]))
    return results[:top_n]


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _entropy_label(e: float) -> str:
    if e >= THRESHOLD_CRIT:
        return "CRITICAL"
    if e >= THRESHOLD_HIGH:
        return "HIGH"
    if e >= THRESHOLD_WARN:
        return "ELEVATED"
    return "OK"


def _entropy_color(e: float) -> str:
    if e >= THRESHOLD_CRIT:
        return "red"
    if e >= THRESHOLD_HIGH:
        return "yellow"
    if e >= THRESHOLD_WARN:
        return "cyan"
    return "green"


def _heatmap_char(e: float) -> str:
    idx = int((e / 8.0) * (len(HEATMAP_CHARS) - 1))
    return HEATMAP_CHARS[min(idx, len(HEATMAP_CHARS) - 1)]


def render_heatmap_plain(entries: list[float], width: int = 64) -> str:
    """Render a single-row ASCII heatmap of entropy across the file."""
    if not entries:
        return ""
    # Downsample or upsample to `width` columns
    ratio = len(entries) / width
    cols = []
    for i in range(width):
        idx = int(i * ratio)
        idx = min(idx, len(entries) - 1)
        cols.append(_heatmap_char(entries[idx]))
    bar = "".join(cols)
    return f"  [{bar}]"


def render_heatmap_rich(entries: list[float], width: int = 64) -> str:
    """Rich-markup colored heatmap."""
    if not entries:
        return ""
    ratio = len(entries) / width
    parts = []
    for i in range(width):
        idx = int(i * ratio)
        idx = min(idx, len(entries) - 1)
        e = entries[idx]
        c = _entropy_color(e)
        ch = _heatmap_char(e)
        parts.append(f"[{c}]{ch}[/{c}]")
    return "  [" + "".join(parts) + "]"


# ---------------------------------------------------------------------------
# Plain output
# ---------------------------------------------------------------------------

def render_plain(
    filepath: str,
    data: bytes,
    blocks: list[tuple[int, int, float]],
    slide: list[float],
    xor_results: Optional[list[dict]],
    key_len: int,
    args,
) -> None:
    ent = shannon_entropy(data)
    sha = hashlib.sha256(data).hexdigest()
    chi = chi_square(data)
    label = _entropy_label(ent)

    print(BANNER)
    print(f"  File     : {filepath}")
    print(f"  Size     : {len(data):,} bytes")
    print(f"  SHA256   : {sha}")
    print()
    print(f"  Entropy  : {ent:.4f} bits/byte  [{label}]")
    print(f"  Chi²     : {chi:.2f}")
    print()
    print(f"  Thresholds:")
    print(f"    {THRESHOLD_WARN:.1f}  → ELEVATED  (watchlist range)")
    print(f"    {THRESHOLD_HIGH:.1f}  → HIGH      (common EDR alert threshold)")
    print(f"    {THRESHOLD_CRIT:.1f}  → CRITICAL  (most EDRs flag this range)")
    print()

    # Heatmap
    print("  Entropy heatmap (left=file start, right=file end):")
    print(render_heatmap_plain(slide))
    print(f"  0.0{'':50}8.0")
    print()

    # Block breakdown
    print(f"  Block breakdown ({args.block_size}B blocks):")
    print(f"  {'Offset':<12} {'Size':<8} {'Entropy':<10} {'Status'}")
    print(f"  {'-'*50}")
    for offset, size, e in blocks:
        lbl = _entropy_label(e)
        flag = " ◄" if e >= THRESHOLD_WARN else ""
        print(f"  {hex(offset):<12} {size:<8} {e:<10.4f} {lbl}{flag}")
    print()

    # Byte distribution stats
    dist = byte_distribution(data)
    nonzero = sum(1 for c in dist if c > 0)
    top5 = sorted(enumerate(dist), key=lambda x: -x[1])[:5]
    print(f"  Byte distribution:")
    print(f"    Unique bytes used : {nonzero}/256")
    print(f"    Top 5 bytes       : " +
          ", ".join(f"0x{b:02x}({c})" for b, c in top5))
    print()

    # XOR results
    if xor_results:
        orig_ent = shannon_entropy(data)
        print(f"  XOR key analysis  (key_len={key_len}, original entropy={orig_ent:.4f}):")
        print(f"  {'Rank':<6} {'Key (hex)':<20} {'Key Entropy':<14} {'Result Entropy':<16} {'Delta':<10} {'Below {:.1f}?'.format(THRESHOLD_WARN)}")
        print(f"  {'-'*75}")
        for i, r in enumerate(xor_results, 1):
            below = "✓" if r["below_target"] else ""
            print(f"  {i:<6} {r['key_hex']:<20} {r['key_entropy']:<14} {r['result_entropy']:<16} {r['delta']:<10.4f} {below}")
        print()
        best = xor_results[0]
        if best["below_target"]:
            print(f"  [+] Best key 0x{best['key_hex']} reduces entropy to {best['result_entropy']:.4f} "
                  f"(Δ -{best['delta']:.4f})")
        else:
            print(f"  [!] No tested key brings entropy below {THRESHOLD_WARN} threshold.")
            print(f"      Best result: 0x{best['key_hex']} → {best['result_entropy']:.4f}")


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

def render_rich(
    filepath: str,
    data: bytes,
    blocks: list[tuple[int, int, float]],
    slide: list[float],
    xor_results: Optional[list[dict]],
    key_len: int,
    args,
) -> None:
    ent = shannon_entropy(data)
    sha = hashlib.sha256(data).hexdigest()
    chi = chi_square(data)
    label = _entropy_label(ent)
    ec = _entropy_color(ent)

    console.print(BANNER, style="bold red")

    # Summary panel
    summary = (
        f"[bold]File:[/bold]    {filepath}\n"
        f"[bold]Size:[/bold]    {len(data):,} bytes\n"
        f"[bold]SHA256:[/bold]  {sha}\n\n"
        f"[bold]Entropy:[/bold] [{ec}]{ent:.4f} bits/byte[/{ec}]  "
        f"[bold][{ec}]{label}[/{ec}][/bold]\n"
        f"[bold]Chi²:[/bold]    {chi:.2f}  "
        f"[dim](lower = more uniform byte distribution)[/dim]\n\n"
        f"[dim]Thresholds: "
        f"[cyan]{THRESHOLD_WARN}[/cyan]=ELEVATED  "
        f"[yellow]{THRESHOLD_HIGH}[/yellow]=HIGH  "
        f"[red]{THRESHOLD_CRIT}[/red]=CRITICAL[/dim]"
    )
    console.print(Panel(summary, title="[bold cyan]Target[/bold cyan]", border_style="cyan"))

    # Heatmap
    heatmap = render_heatmap_rich(slide)
    console.print(Panel(
        f"[dim]Low entropy ← {'─'*20} → High entropy[/dim]\n{heatmap}",
        title="[bold]Entropy Heatmap[/bold]",
        border_style="dim",
    ))

    # Block table
    table = Table(show_header=True, header_style="bold magenta",
                  box=box.SIMPLE, padding=(0, 1))
    table.add_column("Offset", style="cyan", width=12)
    table.add_column("Size", width=8)
    table.add_column("Entropy", width=10)
    table.add_column("Status")

    for offset, size, e in blocks:
        lbl = _entropy_label(e)
        ec2 = _entropy_color(e)
        flag = " ◄" if e >= THRESHOLD_WARN else ""
        table.add_row(
            hex(offset),
            str(size),
            f"[{ec2}]{e:.4f}[/{ec2}]",
            f"[{ec2}]{lbl}[/{ec2}]{flag}",
        )

    console.print(Panel(table, title=f"[bold]Block Breakdown[/bold] [dim]({args.block_size}B blocks)[/dim]",
                        border_style="dim"))

    # Byte distribution
    dist = byte_distribution(data)
    nonzero = sum(1 for c in dist if c > 0)
    top5 = sorted(enumerate(dist), key=lambda x: -x[1])[:5]
    dist_text = (
        f"[bold]Unique bytes used:[/bold] {nonzero}/256\n"
        f"[bold]Top 5 bytes:[/bold] " +
        "  ".join(f"[cyan]0x{b:02x}[/cyan]({c})" for b, c in top5)
    )
    console.print(Panel(dist_text, title="[bold]Byte Distribution[/bold]", border_style="dim"))

    # XOR results
    if xor_results:
        orig_ent = shannon_entropy(data)
        xor_table = Table(show_header=True, header_style="bold magenta",
                          box=box.SIMPLE, padding=(0, 1))
        xor_table.add_column("Rank", width=6)
        xor_table.add_column("Key (hex)", width=20)
        xor_table.add_column("Key Entropy", width=13)
        xor_table.add_column("Result Entropy", width=15)
        xor_table.add_column("Delta", width=10)
        xor_table.add_column(f"< {THRESHOLD_WARN:.1f}?", width=8)

        for i, r in enumerate(xor_results, 1):
            below_str = "[green]✓[/green]" if r["below_target"] else "[dim]✗[/dim]"
            rec = _entropy_color(r["result_entropy"])
            xor_table.add_row(
                str(i),
                r["key_hex"],
                str(r["key_entropy"]),
                f"[{rec}]{r['result_entropy']}[/{rec}]",
                f"{r['delta']:+.4f}",
                below_str,
            )

        best = xor_results[0]
        subtitle = (
            f"[green]Best key 0x{best['key_hex']} → entropy {best['result_entropy']:.4f}  (Δ {best['delta']:+.4f})[/green]"
            if best["below_target"]
            else f"[yellow]No key below {THRESHOLD_WARN} threshold — best: 0x{best['key_hex']} → {best['result_entropy']:.4f}[/yellow]"
        )
        console.print(Panel(
            xor_table,
            title=f"[bold]XOR Key Analysis[/bold] [dim](key_len={key_len}, original={orig_ent:.4f})[/dim]",
            subtitle=subtitle,
            border_style="dim",
        ))


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def render_json(
    filepath: str,
    data: bytes,
    blocks: list[tuple[int, int, float]],
    slide: list[float],
    xor_results: Optional[list[dict]],
    key_len: int,
) -> None:
    dist = byte_distribution(data)
    out = {
        "file": filepath,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon_entropy(data), 6),
        "chi_square": round(chi_square(data), 4),
        "label": _entropy_label(shannon_entropy(data)),
        "thresholds": {
            "elevated": THRESHOLD_WARN,
            "high": THRESHOLD_HIGH,
            "critical": THRESHOLD_CRIT,
        },
        "blocks": [
            {"offset": o, "size": s, "entropy": round(e, 6), "label": _entropy_label(e)}
            for o, s, e in blocks
        ],
        "sliding_window": [round(e, 4) for e in slide],
        "byte_distribution": {
            "unique_bytes": sum(1 for c in dist if c > 0),
            "top_10": [
                {"byte": hex(b), "count": c}
                for b, c in sorted(enumerate(dist), key=lambda x: -x[1])[:10]
            ],
        },
        "xor_analysis": None,
    }
    if xor_results:
        out["xor_analysis"] = {
            "key_length": key_len,
            "target_threshold": THRESHOLD_WARN,
            "results": [
                {
                    "key_hex": r["key_hex"],
                    "key_entropy": r["key_entropy"],
                    "result_entropy": r["result_entropy"],
                    "delta": r["delta"],
                    "below_target": r["below_target"],
                }
                for r in xor_results
            ],
        }
    print(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="entropix",
        description="Payload entropy profiler and XOR transform analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  entropix beacon.bin
  entropix shellcode.bin --xor --key-len 4
  entropix implant.bin --xor --key-len 8 --top 20
  entropix payload.bin --format json | tee report.json
  entropix payload.bin --block-size 128 --window 32
""",
    )

    parser.add_argument("target",
                        help="Shellcode blob or binary to analyze")
    parser.add_argument("--block-size", "-b", type=int, default=BLOCK_SIZE_DEFAULT,
                        metavar="N",
                        help=f"Block size for per-region entropy (default: {BLOCK_SIZE_DEFAULT})")
    parser.add_argument("--window", "-w", type=int, default=WINDOW_SIZE_DEFAULT,
                        metavar="N",
                        help=f"Sliding window size for heatmap (default: {WINDOW_SIZE_DEFAULT})")
    parser.add_argument("--xor", "-x", action="store_true",
                        help="Run XOR key analysis to find entropy-reducing keys")
    parser.add_argument("--key-len", "-k", type=int, default=4, metavar="N",
                        help="XOR key length in bytes to evaluate (default: 4)")
    parser.add_argument("--top", "-n", type=int, default=10, metavar="N",
                        help="Number of top XOR key candidates to show (default: 10)")
    parser.add_argument("--format", "-f",
                        choices=["rich", "plain", "json"], default="rich",
                        help="Output format (default: rich)")

    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"[!] File not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    with open(target, "rb") as fh:
        data = fh.read()

    if not data:
        print("[!] File is empty.", file=sys.stderr)
        sys.exit(1)

    # Analysis
    blocks = block_entropy(data, args.block_size)
    slide  = sliding_entropy(data, args.window)
    xor_results = find_best_xor_keys(data, args.key_len, args.top) if args.xor else None

    fmt = args.format
    if fmt == "json":
        render_json(args.target, data, blocks, slide, xor_results, args.key_len)
    elif fmt == "plain" or (fmt == "rich" and not HAS_RICH):
        render_plain(args.target, data, blocks, slide, xor_results, args.key_len, args)
    else:
        render_rich(args.target, data, blocks, slide, xor_results, args.key_len, args)


if __name__ == "__main__":
    main()
