#!/usr/bin/env python3
"""Restore mirrored file_registry content into the (reinstalled) Rust canister.

- Small files (<= 1.3 MB) are grouped into admin_restore_files batches.
- Large files go through store_file_chunk + finalize_chunked_file_step.
- Published flags derived from the pre-cutover catalogs:
    * ext/{id}/{ver}: published iff listed in pre_list_extensions
    * codex/{id}/{ver}: published iff (id, ver) in pre_list_codices
    * everything else: published (legacy default-true semantics)
- ACL re-granted from pre_get_acl.json.

Restartable: pass --skip-until <n> to resume from batch n (batches are
deterministic). Progress is also tracked in /tmp/fr_cutover/restore_done.txt.
"""
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import subprocess
import sys
import threading

CID = "iebdk-kqaaa-aaaau-agoxq-cai"
NETWORK = "staging"
ROOT = "/tmp/fr_cutover/mirror"
BATCH_PAYLOAD = 1_300_000      # raw bytes per admin_restore_files call
BIG_FILE = 1_400_000           # above this -> chunked upload
CHUNK = 1_000_000              # raw bytes per store_file_chunk call
WORKERS = 6
DONE_FILE = "/tmp/fr_cutover/restore_done.txt"

lock = threading.Lock()
done_set = set()
if os.path.exists(DONE_FILE):
    done_set = set(open(DONE_FILE).read().split())


def mark_done(job_id):
    with lock:
        done_set.add(job_id)
        with open(DONE_FILE, "a") as f:
            f.write(job_id + "\n")


def dfx_update(method, payload_text):
    arg_file = f"/tmp/fr_cutover/arg_{threading.get_ident()}.did"
    with open(arg_file, "w") as f:
        f.write("(" + json.dumps(payload_text) + ")")
    for attempt in range(4):
        res = subprocess.run(
            ["dfx", "canister", "call", "--output", "json", CID, method,
             "--argument-file", arg_file, "--network", NETWORK],
            capture_output=True, text=True, cwd="/srv/dev/realms",
            env={**os.environ, "DFX_WARNING": "-mainnet_plaintext_identity"},
        )
        if res.returncode == 0:
            r = json.loads(json.loads(res.stdout))
            if isinstance(r, dict) and r.get("error"):
                raise RuntimeError(f"{method}: {r['error']}")
            return r
        if attempt == 3:
            raise RuntimeError(f"{method} failed: {res.stderr[-500:]}")


def blob(ns, path):
    fp = f"{ROOT}/blobs/" + hashlib.sha256(f"{ns}\n{path}".encode()).hexdigest()
    return open(fp, "rb").read()


def build_jobs():
    manifest = json.load(open(f"{ROOT}/manifest.json"))
    ns_meta = {n["namespace"]: n for n in json.loads(
        json.loads(open("/tmp/fr_cutover/namespaces_raw.json").read()))}

    exts = json.load(open("/tmp/fr_cutover/pre_list_extensions.json"))
    cods = json.load(open("/tmp/fr_cutover/pre_list_codices.json"))
    published = {f"ext/{e['ext_id']}/{v}" for e in exts for v in e["versions"]}
    published |= {f"codex/{c['codex_id']}/{v}" for c in cods for v in c["versions"]}

    def is_published(ns):
        if ns.startswith(("ext/", "codex/")):
            return ns in published
        return True  # legacy default-true for wasm/branding/frontend/...

    # Restore order: consumer-critical namespaces first.
    def order(ns):
        for i, pfx in enumerate(["wasm", "casals-templates", "ext/", "codex/",
                                 "branding", "frontend/"]):
            if ns.startswith(pfx):
                return (i, ns)
        return (9, ns)

    jobs = []
    for ns in sorted(manifest, key=order):
        files = manifest[ns]["files"]
        desc = ns_meta.get(ns, {}).get("description", "")
        pub = is_published(ns)
        batch, batch_bytes = [], 0

        def flush():
            nonlocal batch, batch_bytes
            if batch:
                jobs.append(("batch", ns, pub, desc, batch))
                batch, batch_bytes = [], 0

        for path in sorted(files):
            meta = files[path]
            if meta["size"] > BIG_FILE:
                jobs.append(("big", ns, pub, desc, [(path, meta)]))
                continue
            if batch_bytes + meta["size"] > BATCH_PAYLOAD:
                flush()
            batch.append((path, meta))
            batch_bytes += meta["size"]
        flush()
        if not files:  # empty namespace: restore its record anyway
            jobs.append(("batch", ns, pub, desc, []))
    return jobs


def run_batch(ns, pub, desc, entries):
    payload = {
        "namespace": ns,
        "publish": pub,
        "description": desc,
        "files": [
            {
                "path": path,
                "content_b64": base64.b64encode(blob(ns, path)).decode(),
                "content_type": meta.get("content_type", ""),
                "sha256": meta.get("sha256", ""),
                "updated": meta.get("updated", 0),
            }
            for path, meta in entries
        ],
    }
    r = dfx_update("admin_restore_files", json.dumps(payload))
    assert r.get("ok"), r


def run_big(ns, pub, desc, entries):
    (path, meta), = entries
    data = blob(ns, path)
    chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
    for i, c in enumerate(chunks):
        dfx_update("store_file_chunk", json.dumps({
            "namespace": ns, "path": path, "chunk_index": i,
            "total_chunks": len(chunks),
            "data_b64": base64.b64encode(c).decode(),
            "content_type": meta.get("content_type", ""),
        }))
    r = dfx_update("finalize_chunked_file_step", json.dumps({
        "namespace": ns, "path": path,
        "expected_sha256": meta.get("sha256", ""),
    }))
    assert r.get("done"), r
    # ensure publish/description recorded even if only big files in ns
    dfx_update("admin_restore_files", json.dumps(
        {"namespace": ns, "publish": pub, "description": desc, "files": []}))


def main():
    jobs = build_jobs()
    print(f"{len(jobs)} restore jobs")
    counter = [0]

    def work(idx_job):
        idx, job = idx_job
        kind, ns, pub, desc, entries = job
        job_id = f"{idx}:{kind}:{ns}:{entries[0][0] if entries else '-'}"
        job_key = hashlib.sha256(job_id.encode()).hexdigest()[:16]
        if job_key in done_set:
            return
        if kind == "batch":
            run_batch(ns, pub, desc, entries)
        else:
            run_big(ns, pub, desc, entries)
        mark_done(job_key)
        with lock:
            counter[0] += 1
            if counter[0] % 20 == 0:
                print(f"  {counter[0]}/{len(jobs)} jobs done")

    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(work, enumerate(jobs)))

    # ACL re-grants
    acl = json.load(open("/tmp/fr_cutover/pre_get_acl.json"))
    grants = [(ns, p) for ns, plist in acl.items() for p in plist]
    print(f"re-granting {len(grants)} ACL entries")

    def grant(g):
        ns, principal = g
        r = dfx_update("grant_publish",
                       json.dumps({"namespace": ns, "principal": principal}))
        assert r.get("ok"), r

    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        list(ex.map(grant, grants))

    print("RESTORE COMPLETE")


if __name__ == "__main__":
    sys.exit(main())
