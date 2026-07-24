#!/usr/bin/env bash
# End-to-end smoke test against a locally deployed file_registry canister.
# Requires: dfx deploy file_registry (done), python3, curl.
set -euo pipefail
cd "$(dirname "$0")/.."

CID=$(dfx canister id file_registry)
PORT=$(dfx info webserver-port)
BASE="http://${CID}.localhost:${PORT}"
TMP=/tmp/fr_e2e
mkdir -p "$TMP"

# Build a candid argument file: ("<json-escaped payload>")
mk_arg() { # mk_arg <json-payload-file> <out.did>
  python3 -c 'import json, sys
payload = open(sys.argv[1]).read()
open(sys.argv[2], "w").write("(" + json.dumps(payload) + ")")' "$1" "$2"
}

call_f() { # call_f <method> <json-payload-file>
  mk_arg "$2" "$2.did"
  dfx canister call --output json "$CID" "$1" --argument-file "$2.did"
}

call() { # call <method> <json-payload-string>
  printf '%s' "$2" > "$TMP/args.json"
  call_f "$1" "$TMP/args.json"
}

check() { # check <python-assert-expr reading r>
  python3 -c "import json, sys
r = json.loads(json.loads(sys.stdin.read()))
assert $1, r
print('   ok:', json.dumps(r)[:160])"
}

echo "== 1. store_file (small) =="
python3 -c 'import json, base64
print(json.dumps({
  "namespace": "ext/demo/1.0.0",
  "path": "manifest.json",
  "content_b64": base64.b64encode(json.dumps({"name": "demo", "version": "1.0.0"}).encode()).decode(),
}))' > "$TMP/store.json"
call_f store_file "$TMP/store.json" | check 'r.get("ok")'

echo "== 2. chunked upload (3.5 MB in 512 KB chunks) =="
NCHUNKS=$(python3 -c 'import base64, hashlib, json, os
blob = os.urandom(3_500_000)
open("/tmp/fr_e2e/blob.bin", "wb").write(blob)
open("/tmp/fr_e2e/blob.sha", "w").write(hashlib.sha256(blob).hexdigest())
csize = 512 * 1024
chunks = [blob[i:i+csize] for i in range(0, len(blob), csize)]
for i, c in enumerate(chunks):
    args = {"namespace": "wasm", "path": "realm-base-9.9.9.wasm",
            "chunk_index": i, "total_chunks": len(chunks),
            "data_b64": base64.b64encode(c).decode()}
    open(f"/tmp/fr_e2e/chunk_{i}.json", "w").write(json.dumps(args))
fin = {"namespace": "wasm", "path": "realm-base-9.9.9.wasm",
       "expected_sha256": hashlib.sha256(blob).hexdigest(), "batch_size": 1}
open("/tmp/fr_e2e/finalize.json", "w").write(json.dumps(fin))
print(len(chunks))')
EXPECTED_SHA=$(cat "$TMP/blob.sha")
for i in $(seq 0 $((NCHUNKS - 1))); do
  call_f store_file_chunk "$TMP/chunk_$i.json" | check 'r.get("ok")'
done
call_f finalize_chunked_file_step "$TMP/finalize.json" \
  | check 'r.get("ok") and r.get("done") and r["sha256"] == open("/tmp/fr_e2e/blob.sha").read()'

echo "== 3. publish + catalogs =="
call publish_namespace '{"namespace": "ext/demo/1.0.0"}' | check 'r.get("ok")'
dfx canister call --output json --query "$CID" list_extensions '()' \
  | check 'r[0]["ext_id"] == "demo" and r[0]["manifest"]["name"] == "demo"'
call latest_version '{"category": "ext", "item_id": "demo"}' \
  | check 'r["latest"] == "1.0.0" and r["namespace"] == "ext/demo/1.0.0"'
dfx canister call --output json --query "$CID" get_backend_files_icc '("ext", "demo", "")' \
  | check 'r["file_count"] == 1 and "manifest.json" in r["files"]'

echo "== 4. chunked read back (get_file_chunk_icc) and hash check =="
python3 - "$CID" "$EXPECTED_SHA" <<'EOF'
import base64, hashlib, json, subprocess, sys
cid, expected = sys.argv[1], sys.argv[2]
out = bytearray()
offset = 0
while True:
    res = subprocess.run(
        ["dfx", "canister", "call", "--output", "json", "--query", cid,
         "get_file_chunk_icc",
         f'("wasm", "realm-base-9.9.9.wasm", "{offset}", "1048576")'],
        capture_output=True, text=True, check=True)
    r = json.loads(json.loads(res.stdout))
    assert "error" not in r, r
    out.extend(base64.b64decode(r["content_b64"]))
    offset += r["length"]
    if r["eof"]:
        break
actual = hashlib.sha256(bytes(out)).hexdigest()
assert actual == expected, (actual, expected)
print(f"   ok: read {len(out)} bytes in chunked mode, sha256 matches")
EOF

echo "== 5. HTTP certified reads =="
curl -sf "$BASE/" | python3 -c 'import json,sys
r = json.load(sys.stdin)
names = [n["namespace"] for n in r]
assert "ext/demo/1.0.0" in names and "wasm" in names, names
print("   ok: GET / ->", names)'
curl -sf "$BASE/api/extensions" | python3 -c 'import json,sys
r = json.load(sys.stdin); assert r[0]["ext_id"] == "demo", r; print("   ok: GET /api/extensions")'
curl -sf "$BASE/ext/demo/1.0.0" | python3 -c 'import json,sys
r = json.load(sys.stdin); assert r[0]["path"] == "manifest.json", r; print("   ok: GET /{ns} listing")'
curl -sf "$BASE/ext/demo/1.0.0/manifest.json" | python3 -c 'import json,sys
r = json.load(sys.stdin); assert r["name"] == "demo", r; print("   ok: GET file ->", r)'
echo "   headers:"
curl -sfI "$BASE/ext/demo/1.0.0/manifest.json" | grep -iE "access-control-allow-origin|content-type|cache-control" | sed 's/^/     /'

echo "== 6. large file over HTTP (streamed) =="
curl -sf "$BASE/wasm/realm-base-9.9.9.wasm" -o "$TMP/http.bin"
python3 - "$EXPECTED_SHA" <<'EOF'
import hashlib, sys
actual = hashlib.sha256(open("/tmp/fr_e2e/http.bin", "rb").read()).hexdigest()
assert actual == sys.argv[1], (actual, sys.argv[1])
print("   ok: 3.5 MB HTTP download sha256 matches")
EOF

echo "== 7. get_stats =="
dfx canister call --output json --query "$CID" get_stats '()' \
  | check 'r["total_files"] >= 2'

echo
echo "ALL E2E CHECKS PASSED"
