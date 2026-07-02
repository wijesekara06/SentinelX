#!/usr/bin/env python3
"""
SentinelX — Latency Benchmark (NFR-01)
=======================================
NFR-01 requires: "no more than 50 milliseconds of additional processing
latency per HTTP request during honeypot analysis" (up to 500 concurrent
connections).

This script measures the first half of that claim rigorously: the extra
time the honeypot's analysis pipeline (pattern detection -> CVE
correlation -> risk scoring -> encrypted logging -> alert generation)
adds on top of baseline Flask/TLS overhead. It does this by comparing
/api/health (near-zero processing) against a real attack payload sent
to a live decoy endpoint (full pipeline), over a kept-alive connection
so TLS handshake cost doesn't dominate the measurement.

It also runs a modest concurrency sanity check. That is NOT the same
claim as "validated at 500 concurrent connections" -- a real test of
that figure needs dedicated load-testing tooling (Locust, wrk) against
a production (Gunicorn) deployment, not a script against the Flask dev
server. The output says so explicitly rather than implying otherwise.

NOTE: each run of this script sends real attack payloads to the
honeypot, so it adds ~N new entries to alerts.json / honeypot_activity.log
(same accumulation behavior as running test_all_features.py). Clear
those files first if you want a clean baseline for a demo.

Run with the honeypot already started:
    python run_all.py                        (in another terminal)
    python tests/benchmark_latency.py

Author: Naveesha Pathirathna (CVE Analyst / Security)
"""

import statistics
import sys
import time
import concurrent.futures
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HP = "https://localhost:5001"
S  = {"verify": False}   # self-signed cert

N            = 100   # timed requests per batch
WARMUP       = 5     # untimed requests before each timed batch
CONCURRENCY  = 50     # simultaneous requests for the sanity check
NFR01_BUDGET_MS = 50


def timed_requests(session, method, url, n, **kwargs):
    """Fire n sequential requests over a kept-alive session, return latencies in ms."""
    latencies = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = session.request(method, url, timeout=5, **kwargs)
        t1 = time.perf_counter()
        r.raise_for_status()
        latencies.append((t1 - t0) * 1000)
    return latencies


def percentile(data, p):
    data = sorted(data)
    k = (len(data) - 1) * (p / 100)
    f, c = int(k), min(int(k) + 1, len(data) - 1)
    if f == c:
        return data[f]
    return data[f] + (data[c] - data[f]) * (k - f)


def report(name, latencies):
    print(f"  {name}")
    print(f"    mean: {statistics.mean(latencies):6.2f} ms")
    print(f"    p50:  {percentile(latencies, 50):6.2f} ms")
    print(f"    p95:  {percentile(latencies, 95):6.2f} ms")
    print(f"    max:  {max(latencies):6.2f} ms")


def main():
    print("=" * 60)
    print("  SentinelX -- Latency Benchmark (NFR-01)")
    print("=" * 60)
    print(f"  {N} timed requests per batch, {WARMUP} warm-up requests discarded")
    print(f"  (this run will add ~{N} new entries to alerts.json / honeypot_activity.log)")
    print()

    session = requests.Session()

    try:
        session.get(f"{HP}/api/health", timeout=5, **S)
    except requests.exceptions.RequestException:
        print(f"Cannot connect to honeypot at {HP}.")
        print("Is it running? Start it with: python run_all.py")
        sys.exit(1)

    # ---- Baseline: /api/health, near-zero processing ----
    timed_requests(session, "GET", f"{HP}/api/health", WARMUP, **S)
    baseline = timed_requests(session, "GET", f"{HP}/api/health", N, **S)
    report("Baseline  (/api/health -- no analysis pipeline)", baseline)
    print()

    # ---- Full pipeline: real attack payload through pattern detection,
    # CVE correlation, risk scoring, encrypted logging, alert generation ----
    payload = {"username": "' OR 1=1--", "password": "x"}
    timed_requests(session, "POST", f"{HP}/admin-login", WARMUP, json=payload, **S)
    pipeline = timed_requests(session, "POST", f"{HP}/admin-login", N, json=payload, **S)
    report("Pipeline  (/admin-login -- SQLi payload, full analysis)", pipeline)
    print()

    # ---- NFR-01 verdict ----
    delta   = statistics.mean(pipeline) - statistics.mean(baseline)
    verdict = "WITHIN BUDGET" if delta <= NFR01_BUDGET_MS else "OVER BUDGET"
    print("=" * 60)
    print(f"  Additional processing latency (mean pipeline - mean baseline):")
    print(f"    {delta:.2f} ms")
    print(f"  NFR-01 budget: {NFR01_BUDGET_MS} ms  ->  {verdict}")
    print("=" * 60)
    print()

    # ---- Concurrency sanity check (NOT a 500-connection validation) ----
    print(f"  Concurrency sanity check ({CONCURRENCY} simultaneous requests)")
    print(f"  This confirms the server stays correct under a modest burst.")
    print(f"  It does NOT validate NFR-01's 500-concurrent-connection figure --")
    print(f"  that needs Locust/wrk against a production Gunicorn deployment,")
    print(f"  not this script against the Flask dev server.")
    print()

    def one_request(_):
        r = requests.post(f"{HP}/admin-login", json=payload, timeout=10, **S)
        return r.status_code

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        results = list(ex.map(one_request, range(CONCURRENCY)))
    t1 = time.perf_counter()

    ok_count = sum(1 for code in results if code == 200)
    print(f"    {ok_count}/{CONCURRENCY} requests succeeded (HTTP 200)")
    print(f"    Batch wall-clock time: {(t1 - t0) * 1000:.1f} ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
