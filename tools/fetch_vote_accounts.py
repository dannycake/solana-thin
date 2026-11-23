#!/usr/bin/env python3
"""Fetch every vote account's stake and BLS key from a Solana RPC node.

Writes the JSON that `ValidatorSet::from_vote_accounts` takes (see
crates/solana-thin/tests/mainnet_snapshot.rs). Standard library only.

    python3 tools/fetch_vote_accounts.py https://api.mainnet-beta.solana.com out.json

What `getVoteAccounts` reports during epoch E is the stake snapshot the
cluster uses to check certificates in epoch E + 1, so run this during the
epoch *before* the one you want a validator set for. Run it against several
independent RPC providers and compare the set hash before pinning it.

Not every staked vote account with a BLS key is in the set. At the first block
of epoch E the cluster keeps only accounts that can pay that epoch's Validator
Admission Ticket (SIMD-0357), burns it from each, and records the burn as a
`VATDebit` reward. Those debits are the exact membership of epoch E + 1's set,
so this reads them from that block and drops every account without one. The
dropped accounts are listed under `not_admitted`. If the block has no debits
(a test cluster in its first epoch, or a node that has pruned the block) every
account is kept and a warning is printed.

Two things can still differ from what the cluster froze at that block: an
account's BLS key and its node identity, both read live here. Run this early
in the epoch.
"""
import base64
import json
import sys
import urllib.request

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + ALPHABET.index(c)
    return n.to_bytes(32, "big")


def rpc(url: str, method: str, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "solana-thin-tools"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        out = json.load(resp)
    if "error" in out:
        raise SystemExit(f"{method}: {out['error']}")
    return out["result"]


def admitted_vote_accounts(url: str, epoch) -> set | None:
    """Vote accounts debited a Validator Admission Ticket in the epoch's first block."""
    first_slot = epoch["absoluteSlot"] - epoch["slotIndex"]
    try:
        # The first slot may have been skipped; take the first block that exists.
        slots = rpc(url, "getBlocks", [first_slot, first_slot + 64, {"commitment": "finalized"}])
        if not slots:
            return None
        block = rpc(
            url,
            "getBlock",
            [
                slots[0],
                {
                    "encoding": "json",
                    "transactionDetails": "none",
                    "rewards": True,
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
    except SystemExit:
        return None
    debited = {r["pubkey"] for r in (block or {}).get("rewards") or [] if r.get("rewardType") == "VATDebit"}
    return debited or None


def main():
    url, out_path = sys.argv[1], sys.argv[2]
    epoch = rpc(url, "getEpochInfo", [{"commitment": "finalized"}])
    admitted = admitted_vote_accounts(url, epoch)
    votes = rpc(url, "getVoteAccounts", [{"commitment": "finalized"}])
    listed = votes["current"] + votes["delinquent"]
    accounts, not_admitted = [], []
    for i in range(0, len(listed), 100):
        chunk = listed[i : i + 100]
        infos = rpc(
            url,
            "getMultipleAccounts",
            [[v["votePubkey"] for v in chunk], {"encoding": "base64", "commitment": "finalized", "dataSlice": {"offset": 0, "length": 193}}],
        )["value"]
        for vote, info in zip(chunk, infos):
            data = base64.b64decode(info["data"][0]) if info else b""
            bls = None
            # VoteStateV4: u32 version tag (3), four pubkeys, two u16, one u64,
            # then Option<[u8; 48]> at offset 144.
            if len(data) >= 193 and int.from_bytes(data[:4], "little") == 3 and data[144] == 1:
                bls = data[145:193].hex()
            account = {
                "vote_pubkey": b58decode(vote["votePubkey"]).hex(),
                "node_pubkey": b58decode(vote["nodePubkey"]).hex(),
                "bls_pubkey": bls,
                "stake": vote["activatedStake"],
            }
            if admitted is None or vote["votePubkey"] in admitted:
                accounts.append(account)
            else:
                not_admitted.append(account)
    doc = {
        "fetched_in_epoch": epoch["epoch"],
        "fetched_at_slot": epoch["absoluteSlot"],
        "admission_checked": admitted is not None,
        "accounts": sorted(accounts, key=lambda a: a["vote_pubkey"]),
        "not_admitted": sorted(not_admitted, key=lambda a: a["vote_pubkey"]),
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, separators=(",", ":"))
    with_key = sum(1 for a in accounts if a["bls_pubkey"])
    print(f"epoch {epoch['epoch']}: {len(accounts)} vote accounts, {with_key} with a BLS key")
    if admitted is None:
        print("warning: no admission debits found in the epoch's first block; nothing was filtered")
    else:
        staked = sum(1 for a in not_admitted if a["bls_pubkey"] and a["stake"])
        print(f"{len(admitted)} admission debits; dropped {len(not_admitted)} accounts without one ({staked} of them staked with a BLS key)")
        missing = admitted - {v["votePubkey"] for v in listed}
        if missing:
            print(f"warning: {len(missing)} debited accounts are not in getVoteAccounts")


if __name__ == "__main__":
    main()
