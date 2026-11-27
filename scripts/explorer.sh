#!/usr/bin/env bash
# Assemble the explorer (explorer/) as a directory of static files that any
# web server, or none, can host.
#
#   scripts/explorer.sh [--out DIR] [--connect ORIGIN]... [--sets DIR] [--serve PORT]
#
#   --out DIR         where to write the site (default: <target dir>/explorer)
#   --connect ORIGIN  name a prover the page may talk to, e.g.
#                     https://prover.example.org. Repeat for more. Without
#                     any, the page may ask any https origin or a prover on
#                     this machine, and the reader chooses.
#   --sets DIR        bundle set files (solana-thin/set/v1, as setlog writes
#                     them) so the page needs no prover to load them. They
#                     are still held to the hashes in explorer/trust.json.
#   --serve PORT      serve the result on 127.0.0.1:PORT afterward.
#
# The site is the page, its stylesheet and scripts, the verifier module, the
# pinned set hashes, and an example proof from the mainnet test vector. It
# writes SHA256SUMS beside them, so a published copy can be compared with a
# build from this commit.
#
# Needs the wasm32-unknown-unknown target, a clang that compiles for wasm32
# (blst is C), and python3.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

out=
sets=
serve=
connect=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=$2; shift 2 ;;
    --connect) connect+=("$2"); shift 2 ;;
    --sets) sets=$2; shift 2 ;;
    --serve) serve=$2; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# The real target directory, honoring a cargo config that redirects it.
target=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
out=${out:-$target/explorer}

echo "== the verifier module"
cargo build --locked -p solana-thin-wasm --target wasm32-unknown-unknown --release
module=$target/wasm32-unknown-unknown/release/solana_thin_wasm.wasm

echo "== assembling $out"
mkdir -p "$out"
# Only the files this script writes are replaced; nothing else in $out is touched.
rm -rf "$out/sets" "$out/example"
mkdir -p "$out/sets" "$out/example"
cp explorer/index.html explorer/explorer.js explorer/explorer.css explorer/base58.js \
  explorer/decode.js explorer/trust.json "$out/"
cp crates/solana-thin-wasm/solana-thin.mjs "$module" "$out/"
cp LICENSE "$out/LICENSE"

python3 - "$out" crates/solana-thin/tests/vectors/mainnet-block-473100911.json "$sets" "${connect[@]}" <<'PY'
import json, pathlib, re, sys

out, vector_path, sets_dir, *connect = sys.argv[1:]
out = pathlib.Path(out)
trust = json.loads((out / "trust.json").read_text())
cluster = trust["clusters"]["mainnet-beta"]

# The example: the first transaction of mainnet slot 473,100,911, and the set
# of its epoch, so the page can be tried with nothing but this site.
vector = json.loads(pathlib.Path(vector_path).read_text())
(out / "example" / "proof.bin").write_bytes(bytes.fromhex(vector["proof_of_first_transaction"]))
bundled = {}
bundled[str(vector["epoch"])] = {
    "format": "solana-thin/set/v1",
    "cluster": vector["cluster"],
    "shred_version": vector["shred_version"],
    "epoch": vector["epoch"],
    "set_hash": vector["validator_set_hash"],
    "set": vector["validator_set"],
}
if sets_dir:
    for path in sorted(pathlib.Path(sets_dir).glob("*.json")):
        try:
            file = json.loads(path.read_text())
        except ValueError:
            continue
        if file.get("format") == "solana-thin/set/v1" and file.get("cluster") == "mainnet-beta":
            bundled[str(file["epoch"])] = file
for epoch, file in sorted(bundled.items()):
    pinned = cluster["sets"].get(epoch, {}).get("hash")
    if pinned != file["set_hash"]:
        sys.exit(f"set file for epoch {epoch} hashes to {file['set_hash']}, "
                 f"and trust.json pins {pinned}: refusing to bundle it")
    (out / "sets" / f"{epoch}.json").write_text(json.dumps(file))
(out / "sets" / "index.json").write_text(json.dumps(sorted(bundled, key=int)))
print(f"bundled sets: {', '.join(sorted(bundled, key=int))}")

if connect:
    for origin in connect:
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?", origin):
            sys.exit(f"not an origin: {origin}")
    page = out / "index.html"
    text = page.read_text()
    narrowed = re.sub(r"connect-src [^;]*;", f"connect-src 'self' {' '.join(connect)};", text, count=1)
    assert narrowed != text, "the page's policy has no connect-src to narrow"
    page.write_text(narrowed)
    print(f"connect-src narrowed to: 'self' {' '.join(connect)}")
PY

(cd "$out" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "== done: $(find "$out" -type f | wc -l) files, $(du -sh "$out" | cut -f1)"

if [ -n "$serve" ]; then
  echo "== serving http://127.0.0.1:$serve/"
  exec python3 -m http.server --bind 127.0.0.1 --directory "$out" "$serve"
fi
