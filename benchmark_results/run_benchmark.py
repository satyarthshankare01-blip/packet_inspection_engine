#!/usr/bin/env python3
"""
Reproducible benchmark script for DPI Engine.
Measures single-threaded vs multithreaded performance across configurations.
Usage: python3 run_benchmark.py [pcap_file] [warmup_runs] [measured_runs]
"""

import subprocess
import time
import statistics
import csv
import json
import os
import sys
import platform

# ── Configuration ──────────────────────────────────────────────────────────────
PCAP_FILE = sys.argv[1] if len(sys.argv) > 1 else "benchmark_1m.pcap"
WARMUP_RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 2
MEASURED_RUNS = int(sys.argv[3]) if len(sys.argv) > 3 else 7
OUTPUT_DIR = "benchmark_results"

CONFIGS = [
    {"name": "single-threaded", "label": "ST",
     "cmd": ["./dpi_simple", PCAP_FILE, "/dev/null"]},
    {"name": "mt-1x1 (1 LB, 1 FP)", "label": "MT-1x1",
     "cmd": ["./dpi_engine", PCAP_FILE, "/dev/null", "--lbs", "1", "--fps", "1"]},
    {"name": "mt-2x2 (2 LB, 2 FP/LB = 4 FP)", "label": "MT-2x2",
     "cmd": ["./dpi_engine", PCAP_FILE, "/dev/null", "--lbs", "2", "--fps", "2"]},
    {"name": "mt-2x3 (2 LB, 3 FP/LB = 6 FP)", "label": "MT-2x3",
     "cmd": ["./dpi_engine", PCAP_FILE, "/dev/null", "--lbs", "2", "--fps", "3"]},
]


def get_packet_count(pcap_path):
    """Extract packet count from capinfos."""
    try:
        r = subprocess.run(["capinfos", "-c", pcap_path],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[-1].strip().replace(" ", "").replace("k", "000"))
    except Exception:
        pass
    # Fallback: run dpi_simple and parse
    r = subprocess.run(["./dpi_simple", pcap_path, "/dev/null"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "Total Packets:" in line:
            parts = line.split()
            for p in parts:
                if p.isdigit():
                    return int(p)
    return 0


def run_single(cmd):
    """Run a command, return wall-clock time in seconds."""
    t0 = time.perf_counter()
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t1 = time.perf_counter()
    if r.returncode != 0:
        raise RuntimeError(f"Command failed (rc={r.returncode}): {' '.join(cmd)}")
    return t1 - t0


def benchmark_config(cfg, warmup=WARMUP_RUNS, measured=MEASURED_RUNS):
    """Warm up, then take measured trials."""
    cmd = cfg["cmd"]
    name = cfg["name"]

    print(f"\n  {name}")
    print(f"    Warming up ({warmup} runs)...", end="", flush=True)
    for _ in range(warmup):
        run_single(cmd)
    print(" done")

    print(f"    Measuring ({measured} runs):", end="", flush=True)
    times = []
    for i in range(measured):
        t = run_single(cmd)
        times.append(t)
        print(f" {t*1000:.1f}ms", end="", flush=True)
    print()

    return times


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ── System info ─────────────────────────────────────────────────────────
    cpu_info = "unknown"
    try:
        r = subprocess.run(["lscpu"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "Model name" in line:
                cpu_info = line.split(":")[1].strip()
                break
    except Exception:
        pass

    print("=" * 70)
    print("DPI Engine Benchmark")
    print("=" * 70)
    print(f"  PCAP:           {PCAP_FILE}")
    print(f"  Warmup runs:    {WARMUP_RUNS}")
    print(f"  Measured runs:  {MEASURED_RUNS}")
    print(f"  CPU:            {cpu_info}")
    print(f"  OS:             {platform.platform()}")

    pkt_count = get_packet_count(PCAP_FILE)
    file_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0
    print(f"  Packet count:   {pkt_count:,}")
    print(f"  File size:      {file_size / 1024 / 1024:.1f} MB")
    print("=" * 70)

    # ── Run benchmarks ──────────────────────────────────────────────────────
    all_results = {}
    for cfg in CONFIGS:
        times = benchmark_config(cfg)
        med = statistics.median(times)
        mn = statistics.mean(times)
        sd = statistics.stdev(times) if len(times) > 1 else 0.0
        pps = pkt_count / med if med > 0 else 0

        all_results[cfg["label"]] = {
            "name": cfg["name"],
            "label": cfg["label"],
            "times_ms": [round(t * 1000, 2) for t in times],
            "median_ms": round(med * 1000, 2),
            "mean_ms": round(mn * 1000, 2),
            "stdev_ms": round(sd * 1000, 2),
            "min_ms": round(min(times) * 1000, 2),
            "max_ms": round(max(times) * 1000, 2),
            "packets_per_sec": round(pps),
        }

    # ── Calculate speedup relative to single-threaded ───────────────────────
    st_median = all_results["ST"]["median_ms"]
    for label, r in all_results.items():
        r["speedup"] = round(st_median / r["median_ms"], 3) if r["median_ms"] > 0 else 0
        r["pct_reduction"] = round((1.0 - r["median_ms"] / st_median) * 100, 1) if st_median > 0 else 0

    # ── Print summary table ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    print(f"{'Configuration':<30} {'Median':>10} {'Stdev':>10} {'Pkts/s':>12} {'Speedup':>8} {'Reduction':>10}")
    print("-" * 82)
    for label in ["ST", "MT-1x1", "MT-2x2", "MT-2x3"]:
        r = all_results[label]
        print(f"{r['name']:<30} {r['median_ms']:>8.2f}ms {r['stdev_ms']:>8.2f}ms "
              f"{r['packets_per_sec']:>10,}  {r['speedup']:>7.3f}x {r['pct_reduction']:>8.1f}%")
    print("=" * 70)

    # ── Write CSV ───────────────────────────────────────────────────────────
    csv_path = os.path.join(OUTPUT_DIR, "benchmark_results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["config", "label", "median_ms", "mean_ms", "stdev_ms",
                  "min_ms", "max_ms", "packets_per_sec", "speedup",
                  "pct_reduction"]
        for i in range(MEASURED_RUNS):
            header.append(f"trial_{i+1}_ms")
        writer.writerow(header)
        for label in ["ST", "MT-1x1", "MT-2x2", "MT-2x3"]:
            r = all_results[label]
            row = [r["name"], r["label"], r["median_ms"], r["mean_ms"],
                   r["stdev_ms"], r["min_ms"], r["max_ms"],
                   r["packets_per_sec"], r["speedup"], r["pct_reduction"]]
            row.extend(r["times_ms"])
            writer.writerow(row)
    print(f"\nCSV written to: {csv_path}")

    # ── Write JSON (machine-readable) ───────────────────────────────────────
    json_path = os.path.join(OUTPUT_DIR, "benchmark_results.json")
    meta = {
        "pcap_file": PCAP_FILE,
        "packet_count": pkt_count,
        "file_size_bytes": file_size,
        "warmup_runs": WARMUP_RUNS,
        "measured_runs": MEASURED_RUNS,
        "cpu": cpu_info,
        "os": platform.platform(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": all_results,
    }
    with open(json_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"JSON written to: {json_path}")

    return all_results, meta


if __name__ == "__main__":
    all_results, meta = main()
