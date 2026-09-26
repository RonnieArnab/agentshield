"""Detection eval: python -m evals.run  -> detection rate, false-positive rate, p50/p95 scan latency.
Grow the sets toward ~300 each (e.g. HF datasets deepset/prompt-injections, jackhhao/jailbreak-classification)."""
import asyncio
import json
import pathlib
import statistics
import sys
import time

from agentshield.detect import scan

HERE = pathlib.Path(__file__).parent


def load(name):
    return [json.loads(l)["text"] for l in (HERE / name).read_text().splitlines() if l.strip()]


async def run(threshold=0.8):
    lat, res = [], {}
    for name in ("attacks.jsonl", "safe.jsonl"):
        flagged = 0
        for t in load(name):
            t0 = time.perf_counter()
            score, reasons = await scan(t, threshold)
            lat.append((time.perf_counter() - t0) * 1000)
            if score >= threshold:
                flagged += 1
            elif name == "attacks.jsonl" and "-v" in sys.argv:
                print("MISSED:", t[:90])
            if score >= threshold and name == "safe.jsonl" and "-v" in sys.argv:
                print("FALSE POSITIVE:", t[:90], reasons)
        res[name] = (flagged, len(load(name)))
    (a, na), (s, ns) = res["attacks.jsonl"], res["safe.jsonl"]
    q = statistics.quantiles(lat, n=20)
    print("| metric | value |\n|---|---|")
    print(f"| detection rate | {a / na:.0%} ({a}/{na}) |")
    print(f"| false-positive rate | {s / ns:.0%} ({s}/{ns}) |")
    print(f"| scan latency p50 / p95 | {statistics.median(lat):.1f} ms / {q[18]:.1f} ms |")
    return a / na, s / ns


if __name__ == "__main__":
    asyncio.run(run())
