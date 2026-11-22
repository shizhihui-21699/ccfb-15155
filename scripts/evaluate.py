#!/usr/bin/env python3
"""Evaluate keyhunt against a synthetic image + manifest.

Generates the image (via keyhunt-genimg), runs keyhunt scan --jsonl, then
reports recall (planted keys found), precision (detections that correspond to a
planted structure) and verification (planted keys proven against the sample).
"""
import argparse
import json
import subprocess
import sys
import tempfile
import os
import collections


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return p.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mib", type=int, default=64)
    ap.add_argument("--chunk", default="8M")
    ap.add_argument("--threads", "-t", type=int, default=8)
    ap.add_argument("--keep", action="store_true", help="keep image + outputs")
    ap.add_argument("--all", action="store_true", help="report unverified candidates too")
    ap.add_argument("--genimg", default="./keyhunt-genimg")
    ap.add_argument("--keyhunt", default="./keyhunt")
    args = ap.parse_args()

    d = tempfile.mkdtemp(prefix="keyhunt-eval-")
    img = os.path.join(d, "image.raw")
    man = os.path.join(d, "image.json")
    sample = os.path.join(d, "sample.bin")
    jsonl = os.path.join(d, "out.jsonl")

    run([args.genimg, "-o", img, "-m", man, "--mib", str(args.mib), "--sample", sample])
    extra = ["--all"] if args.all else ["--all"]
    run([args.keyhunt, "scan", img, "--sample", sample, "--jsonl", jsonl,
         "-t", str(args.threads), "--chunk", args.chunk,
         "--report", os.path.join(d, "report.txt")] + extra)

    manifest = json.load(open(man))
    planted = manifest["planted"]
    lines = [json.loads(l) for l in open(jsonl)]

    # Ground truth for symmetric material: keys we expect the scanner to surface.
    expect_keys = collections.defaultdict(list)
    for p in planted:
        if not p["expect_detect"]:
            continue
        expect_keys[p["type"]].append(p)

    sym = [l for l in lines if l["type"] == "symmetric"]
    asym = [l for l in lines if l["type"] == "asymmetric"]

    found_key_hex = collections.Counter()
    for s in sym:
        found_key_hex[s["key"]] += 1

    types = sorted(expect_keys)
    print(f"image {args.mib} MiB, {len(planted)} planted structures")
    print(f"detections: {len(sym)} symmetric, {len(asym)} asymmetric\n")
    print(f"{'planted type':30s} {'n':>3s} {'recovered':>10s}  (structural recall)")
    print("-" * 54)
    total_n = total_found = 0
    misses = []
    for t in types:
        items = expect_keys[t]
        # RSA entries carry the modulus, not a symmetric key; score them against
        # the asymmetric list instead.
        if t.startswith("rsa") or t.startswith("ec") or t.startswith("ed") or \
           t.startswith("x25519") or t.startswith("dsa"):
            continue
        n = len(items)
        f = sum(1 for p in items if found_key_hex.get(p["key_hex"], 0) > 0)
        total_n += n
        total_found += f
        print(f"{t:30s} {n:3d} {f:3d}/{n:<3d}")
        if f < n:
            for p in items:
                if not found_key_hex.get(p["key_hex"]):
                    misses.append((t, p["offset"]))

    if total_n:
        print("-" * 54)
        print(f"{'symmetric total':30s} {total_n:3d} {total_found:3d}/{total_n:<3d}"
              f"  = {100.0*total_found/total_n:5.1f}%")
    for m in misses:
        print(f"  MISS {m[0]} @ 0x{m[1]:x}")

    # Asymmetric coverage against planted containers.
    asym_expect = [p for p in planted if p["expect_detect"] and (
        p["type"].startswith("rsa") or p["type"].startswith("ec") or
        p["type"].startswith("ed") or p["type"].startswith("x25519") or
        p["type"].startswith("dsa"))]
    if asym_expect:
        print(f"\nasymmetric containers planted: {len(asym_expect)}, valid detections: {len(asym)}")
        for a in asym:
            print(f"  0x{a['offset']:08x} kind={a['kind']} curve={a['curve'] or '-':18s} "
                  f"verified={a['verified']} {a['verify_how']}")

    # Precision: a symmetric detection is a false positive if its key is not a
    # planted key AND it does not verify. Verified detections are true by
    # construction (they decrypt the sample).
    plant_keys = {p["key_hex"] for p in planted if p["key_hex"]}
    verified = [s for s in sym if s["verified"]]
    matched = [s for s in sym if s["key"] in plant_keys]
    unverified_unmatched = [s for s in sym if not s["verified"] and s["key"] not in plant_keys]
    print(f"\nprecision:")
    print(f"  symmetric detections    : {len(sym)}")
    print(f"  matching a planted key  : {len(matched)}")
    print(f"  verified against sample : {len(verified)}")
    print(f"  neither                 : {len(unverified_unmatched)}  (candidates, not proofs)")
    if verified:
        for v in verified:
            print(f"  PROVEN 0x{v['offset']:08x} {v['cipher']} key={v['key'][:32]}... "
                  f"plaintext_sha256={v['plaintext_sha256'][:16]}...")

    if args.keep:
        print(f"\nartifacts kept in {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
