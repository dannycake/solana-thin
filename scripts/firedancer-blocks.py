#!/usr/bin/env python3
"""Verify that solana-thin accepts blocks an independent client produced.

The verifier does not care which client led a slot; this checks that in
practice, against a client other than Agave. It finds recent mainnet slots led
by a chosen client — by joining `getLeaderSchedule` (slot -> leader identity)
with `getClusterNodes` (identity -> `clientId`) — and runs `prover fetch` over
them. `prover fetch` fetches each block by its certified id, verifies its
finality certificate against the pinned set, and recomputes its block id, so a
slot that verifies is a block solana-thin accepts from that client.

    scripts/firedancer-blocks.py --rpc URL --set SETFILE [--prover PATH]
        [--client Firedancer] [--count 20] [--min-age 400] [--max-age 9000]

`--client` matches the `getClusterNodes` `clientId` (e.g. Firedancer, Agave,
JitoLabs, HarmonicFiredancer, AgaveBam). The window `--min-age`..`--max-age`
slots behind the tip keeps the slots old enough to be finalized with a
certificate in a later block, young enough to still be held by validators.

Needs the prover binary (cargo build --release -p solana-thin-prover) and
Python 3.11+. Reads only a public RPC node and the repair network the prover
uses.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import urllib.request
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent


def rpc(url: str, method: str, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    request = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "firedancer-blocks"})
    with urllib.request.urlopen(request, timeout=90) as response:
        out = json.load(response)
    if "error" in out:
        raise SystemExit(f"{method}: {out['error']}")
    return out["result"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify blocks produced by a chosen client.")
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--set", required=True, help="the pinned set file for the current epoch")
    ap.add_argument("--prover", default=str(ROOT / "target" / "release" / "prover"))
    ap.add_argument("--client", default="Firedancer", help="getClusterNodes clientId to select")
    ap.add_argument("--count", type=int, default=20, help="slots to verify")
    ap.add_argument("--min-age", type=int, default=400)
    ap.add_argument("--max-age", type=int, default=9000)
    args = ap.parse_args()

    nodes = rpc(args.rpc, "getClusterNodes")
    version_of = {n["pubkey"]: str(n.get("version")) for n in nodes if n.get("clientId") == args.client}
    if not version_of:
        raise SystemExit(f"no cluster nodes with clientId {args.client!r}")
    print(f"{len(version_of)} {args.client} identities on the cluster "
          f"(versions {', '.join(sorted(set(version_of.values())))})")

    epoch = rpc(args.rpc, "getEpochInfo")
    epoch_start = epoch["absoluteSlot"] - epoch["slotIndex"]
    tip = epoch["slotIndex"]
    schedule = rpc(args.rpc, "getLeaderSchedule", [None])

    leader_of = {
        epoch_start + off: leader
        for leader, offsets in schedule.items()
        if leader in version_of
        for off in offsets
        if args.min_age <= tip - off <= args.max_age
    }
    print(f"epoch {epoch['epoch']}: {sum(1 for l in schedule if l in version_of)} of {len(schedule)} "
          f"leaders are {args.client}; {len(leader_of)} of their slots are in the "
          f"{args.min_age}..{args.max_age}-slot window")
    if not leader_of:
        raise SystemExit("no slots to check in the window")
    chosen_slots = sorted(leader_of)[-args.count:]
    print(f"fetching {len(chosen_slots)} of them: {chosen_slots[0]}..{chosen_slots[-1]}\n")

    cmd = [args.prover, "fetch", "--rpc", args.rpc, "--set", args.set, *map(str, chosen_slots)]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    sys.stdout.write(result.stdout)
    if result.stderr.strip():
        sys.stderr.write(result.stderr)

    # A verified slot prints "slot <N>: block <id>, <fast|slow> certificate ...".
    verified = {}
    for line in result.stdout.splitlines():
        m = re.match(r"\s*slot (\d+): block [0-9a-f]+, (fast|slow) certificate", line)
        if m:
            verified[int(m.group(1))] = m.group(2)
    by_version = Counter(version_of.get(leader_of[s], "?") for s in verified)
    by_cert = Counter(verified.values())
    print(f"\n=== {len(verified)} of {len(chosen_slots)} {args.client}-led blocks verified ===")
    print(f"certificates: {dict(by_cert)}")
    print(f"leader versions of the verified blocks: {dict(by_version)}")
    return 0 if len(verified) == len(chosen_slots) else 1


if __name__ == "__main__":
    sys.exit(main())
