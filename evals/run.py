"""Detection eval on the hand-written set and the public deepset set.

    python -m evals.run                     # rules layer only
    python -m evals.run --classifier protectai/deberta-v3-base-prompt-injection-v2   # rules vs rules+classifier
    python -m evals.run -v                  # also print misses and false positives
Needs `pip install .[classifier]` for --classifier. Fetch data with `python -m evals.fetch_datasets`.
"""
import asyncio
import json
import pathlib
import statistics
import sys
import time

from agentshield import detect

HERE = pathlib.Path(__file__).parent
SETS = {"hand-written": ("attacks.jsonl", "safe.jsonl"),
        "deepset": ("data/deepset_attacks.jsonl", "data/deepset_safe.jsonl")}
VERBOSE = "-v" in sys.argv
THRESHOLD = 0.8


def load(name):
    p = HERE / name
    return [json.loads(line)["text"] for line in p.read_text().splitlines() if line.strip()] if p.exists() else []


async def rates(attacks, safe):
    lat, flagged = [], {}
    for label, texts in (("attack", attacks), ("safe", safe)):
        n = 0
        for t in texts:
            t0 = time.perf_counter()
            score, reasons = await detect.scan(t, THRESHOLD)
            lat.append((time.perf_counter() - t0) * 1000)
            hit = score >= THRESHOLD
            n += hit
            if VERBOSE and hit != (label == "attack"):
                print(f"  {'MISSED' if label == 'attack' else 'FALSE POSITIVE'}: {t[:100]!r} {reasons}")
        flagged[label] = n
    return flagged["attack"] / len(attacks), flagged["safe"] / len(safe), lat


async def run_config(name):
    cells, lat = [], []
    for set_name, (a, s) in SETS.items():
        attacks, safe = load(a), load(s)
        if not attacks:
            continue
        det, fp, l = await rates(attacks, safe)
        lat += l
        cells.append(f"{det:.0%} / {fp:.0%}")
    return f"| {name} | " + " | ".join(cells) + f" | {statistics.median(lat):.1f} ms |"


async def main():
    header = "| detector | " + " | ".join(f"{k} ({len(load(v[0]))}+{len(load(v[1]))}) detect / FP"
                                        for k, v in SETS.items() if load(v[0])) + " | median latency |"
    rows = []
    model = sys.argv[sys.argv.index("--classifier") + 1] if "--classifier" in sys.argv else None
    detect.CLASSIFIER = None
    rows.append(await run_config("rules only"))
    if model:
        detect.CLASSIFIER = model
        detect.classify("warm up")  # load the model outside the timing
        rows.append(await run_config(f"rules + {model.split('/')[-1]}"))
    print(header + "\n|" + "---|" * (header.count("|") - 1))
    print("\n".join(rows))


if __name__ == "__main__":
    asyncio.run(main())
