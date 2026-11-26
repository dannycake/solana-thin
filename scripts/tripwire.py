#!/usr/bin/env python3
"""Fails when something the verifier's argument stands on has moved.

The conformance ledger (docs/conformance.toml) ties the verifier to specific
files of one Agave release and to a few facts about mainnet. This checks both:

1. Every Agave file the ledger cites: is it byte-identical between the pinned
   tag and the newest release? A change is not a bug, but each ledger row
   citing that file has to be read again.
2. Mainnet: is it still running the release line the ledger was written
   against, and are the feature gates the argument depends on still in the
   state it assumes?

    python3 scripts/tripwire.py                 # against the newest release
    python3 scripts/tripwire.py --against TAG   # against a tag of your choice
    python3 scripts/tripwire.py --no-mainnet    # skip part 2

Exit status: 0 nothing moved, 1 something moved, 2 could not check.
Needs the `gh` CLI (authenticated or not) and Python 3.11+. Nothing is sent
but anonymous reads of the Agave repository and of a public RPC node.
"""
import base64
import json
import pathlib
import re
import subprocess
import sys
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "conformance.toml"
REPO = "anza-xyz/agave"
DEVELOPMENT = "master"
RPC = "https://api.mainnet-beta.solana.com"
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Feature gates the argument depends on, and the state it assumes on mainnet.
# `active: False` means "must not have a feature account"; a change in either
# direction is reported.
FEATURES = {
    "alpenglow_fast_leader_handover": {
        "active": False,
        "why": "UpdateParent blocks become possible. The verifier refuses them, so some "
        "transactions become unprovable; the block shapes in ledger rows 36 and 43 become "
        "reachable on mainnet, and the verifier already refuses them.",
    },
    "stricter_shred_validation": {
        "active": False,
        "why": "SIMD-0504 changes which shreds validators drop (ledger rows 13, 14, 26, 27).",
    },
    "relax_fee_payer_constraint": {
        "active": None,
        "why": "SIMD-0290: an included transaction may be a no-op that pays no fee "
        "(ledger rows 106, 110). Recorded, not assumed either way.",
    },
    "enforce_correct_proof_size": {
        "active": None,
        "why": "Proof size 6 is enforced at ingest (ledger row 7). The verifier assumes it regardless.",
    },
}


class CannotCheck(Exception):
    pass


def gh(path: str):
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if result.returncode != 0:
        raise CannotCheck(f"gh api {path}: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout)


def rpc(method: str, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(RPC, body, {"content-type": "application/json", "user-agent": "tripwire"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            out = json.load(response)
    except OSError as error:
        raise CannotCheck(f"{method}: {error}") from error
    if "error" in out:
        raise CannotCheck(f"{method}: {out['error']}")
    return out["result"]


def cited_files(ledger) -> dict[str, list[int]]:
    """Agave file -> ledger rows that cite it."""
    files: dict[str, list[int]] = {}
    for check in ledger["check"]:
        for part in check["agave"].split(";"):
            path = part.strip().split(":")[0].strip()
            if "/" in path and path.endswith(".rs"):
                files.setdefault(path, []).append(check["id"])
    return files


def blob(path: str, ref: str):
    """The git blob id of a file at a ref, or None if it is not there."""
    result = subprocess.run(
        ["gh", "api", f"repos/{REPO}/contents/{path}?ref={ref}", "--jq", ".sha"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if "404" in result.stderr or "Not Found" in result.stderr:
            return None
        raise CannotCheck(f"{path}@{ref}: {result.stderr.strip()[:200]}")
    return result.stdout.strip()


def feature_ids(ref: str) -> dict[str, str]:
    content = gh(f"repos/{REPO}/contents/feature-set/src/lib.rs?ref={ref}")
    if content.get("content"):
        text = base64.b64decode(content["content"]).decode()
    else:  # larger than the contents API inlines
        raw = subprocess.run(
            ["gh", "api", f"repos/{REPO}/git/blobs/{content['sha']}", "--jq", ".content"],
            capture_output=True,
            text=True,
        )
        if raw.returncode != 0:
            raise CannotCheck(f"feature-set/src/lib.rs@{ref}: {raw.stderr.strip()[:200]}")
        text = base64.b64decode(raw.stdout).decode()
    found = {}
    for name in FEATURES:
        match = re.search(r"pub mod " + name + r"\s*\{[^}]*?declare_id!\(\"([" + ALPHABET + r"]+)\"\)", text)
        if match:
            found[name] = match.group(1)
    return found


def main() -> int:
    args = sys.argv[1:]
    ledger = tomllib.loads(LEDGER.read_text())
    pinned = ledger["agave_tag"]
    moved: list[str] = []
    try:
        if "--against" in args:
            newest = args[args.index("--against") + 1]
        else:
            newest = gh(f"repos/{REPO}/releases/latest")["tag_name"]
        print(f"ledger pinned to {pinned}; comparing with {newest}")

        files = cited_files(ledger)
        if newest != pinned:
            for path, rows in sorted(files.items()):
                before, after = blob(path, pinned), blob(path, newest)
                if before != after:
                    what = "gone" if after is None else "changed"
                    moved.append(f"{path} {what}: reread ledger rows {', '.join(map(str, sorted(set(rows))))}")
            moved.append(f"a newer release than {pinned} exists: {newest}")
        print(f"{len(files)} cited files checked")

        if "--no-mainnet" not in args:
            version = rpc("getVersion", [])["solana-core"]
            line = ".".join(pinned.lstrip("v").split(".")[:2])
            print(f"mainnet RPC runs {version}")
            if not version.startswith(line + "."):
                moved.append(f"mainnet RPC runs {version}, not the {line} line the ledger was written against")
            # A gate's id can change between releases (fast leader handover was a
            # placeholder in 4.4 and got its real id in 4.5), so ask about every id
            # the name has had: at the newest release and on the development branch.
            ids: dict[str, dict[str, str]] = {}
            for ref in dict.fromkeys([newest, DEVELOPMENT]):
                for name, key in feature_ids(ref).items():
                    ids.setdefault(name, {}).setdefault(key, ref)
            for name, expect in FEATURES.items():
                if name not in ids:
                    print(f"feature {name}: not defined in {newest} or {DEVELOPMENT}")
                    continue
                state = False
                for key, ref in ids[name].items():
                    account = rpc("getAccountInfo", [key, {"encoding": "base64"}])["value"]
                    state |= account is not None
                    print(f"feature {name} ({key}, as of {ref}): {'has an account' if account else 'no account'}")
                if expect["active"] is not None and state != expect["active"]:
                    moved.append(f"feature {name} now {'has' if state else 'has no'} account on mainnet. {expect['why']}")
    except CannotCheck as error:
        print(f"could not check: {error}", file=sys.stderr)
        return 2

    if moved:
        print("\nMOVED:")
        for line in moved:
            print(f"  - {line}")
        return 1
    print("\nnothing moved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
