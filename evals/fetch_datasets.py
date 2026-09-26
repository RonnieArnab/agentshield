"""Download public prompt-injection data into evals/data/ (committed, so evals run offline).

Source: deepset/prompt-injections (Apache-2.0), train + test splits, label 1 = injection.
Labels are noisy: some "injections" are just off-task requests, and a few are German.
"""
import json
import pathlib
import random

import httpx

OUT = pathlib.Path(__file__).parent / "data"
API = "https://datasets-server.huggingface.co/rows"


def rows(dataset: str, split: str):
    out, offset = [], 0
    while True:
        r = httpx.get(API, params={"dataset": dataset, "config": "default", "split": split,
                                   "offset": offset, "length": 100}, timeout=60)
        r.raise_for_status()
        batch = [x["row"] for x in r.json()["rows"]]
        out += batch
        offset += len(batch)
        if not batch or offset >= r.json()["num_rows_total"]:
            return out


def main():
    OUT.mkdir(exist_ok=True)
    data = rows("deepset/prompt-injections", "train") + rows("deepset/prompt-injections", "test")
    attacks = [d["text"] for d in data if d["label"] == 1]
    safe = [d["text"] for d in data if d["label"] == 0]
    random.Random(0).shuffle(safe)
    safe = safe[:len(attacks)]  # balanced
    for name, texts in (("deepset_attacks", attacks), ("deepset_safe", safe)):
        (OUT / f"{name}.jsonl").write_text("".join(json.dumps({"text": t}) + "\n" for t in texts))
        print(f"{name}: {len(texts)}")


if __name__ == "__main__":
    main()
