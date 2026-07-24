#!/usr/bin/env python3
"""Mirror all file_registry content from the staging canister to local disk.

Uses only query calls (get_file_chunk_icc, list_files_icc), verifies each
file against its registry sha256 when present, and writes:

    /tmp/fr_cutover/mirror/manifest.json   {ns: {"files": {path: meta}}}
    /tmp/fr_cutover/mirror/blobs/<sha-or-nsid>/...

Restartable: files already on disk with matching size are skipped.
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
CHUNK = 128 * 1024
WORKERS = 8

os.makedirs(f"{ROOT}/blobs", exist_ok=True)
print_lock = threading.Lock()


def dfx_query(method, candid_args):
    for attempt in range(4):
        res = subprocess.run(
            ["dfx", "canister", "call", "--output", "json", "--query",
             CID, method, candid_args, "--network", NETWORK],
            capture_output=True, text=True, cwd="/srv/dev/realms",
            env={**os.environ, "DFX_WARNING": "-mainnet_plaintext_identity"},
        )
        if res.returncode == 0:
            return json.loads(json.loads(res.stdout))
        if attempt == 3:
            raise RuntimeError(f"{method} failed: {res.stderr[-400:]}")


def candid_text(*args):
    return "(" + ", ".join(json.dumps(a) for a in args) + ")"


def blob_path(ns, path):
    safe = hashlib.sha256(f"{ns}\n{path}".encode()).hexdigest()
    return f"{ROOT}/blobs/{safe}"


def fetch_file(ns, path, meta):
    fp = blob_path(ns, path)
    if os.path.exists(fp) and os.path.getsize(fp) == meta["size"]:
        return "cached"
    out = bytearray()
    offset = 0
    while True:
        r = dfx_query("get_file_chunk_icc",
                      candid_text(ns, path, str(offset), str(CHUNK)))
        if "error" in r:
            raise RuntimeError(f"{ns}/{path}: {r}")
        out.extend(base64.b64decode(r["content_b64"]))
        offset += r["length"]
        if r["eof"]:
            break
    if len(out) != meta["size"]:
        raise RuntimeError(f"{ns}/{path}: size {len(out)} != {meta['size']}")
    if meta.get("sha256"):
        actual = hashlib.sha256(bytes(out)).hexdigest()
        if actual != meta["sha256"]:
            raise RuntimeError(f"{ns}/{path}: sha mismatch {actual}")
    with open(fp, "wb") as f:
        f.write(bytes(out))
    return "fetched"


def main():
    namespaces = [n["namespace"] for n in json.loads(
        json.loads(open("/tmp/fr_cutover/namespaces_raw.json").read()))]
    print(f"{len(namespaces)} namespaces")

    manifest = {}
    if os.path.exists(f"{ROOT}/manifest.json"):
        manifest = json.load(open(f"{ROOT}/manifest.json"))

    # 1. File listings per namespace
    for i, ns in enumerate(namespaces):
        if ns in manifest:
            continue
        files = dfx_query("list_files_icc", candid_text(ns))
        manifest[ns] = {"files": {f["path"]: f for f in files}}
        if i % 25 == 0:
            print(f"  listed {i}/{len(namespaces)}")
    json.dump(manifest, open(f"{ROOT}/manifest.json", "w"))
    total_files = sum(len(v["files"]) for v in manifest.values())
    total_bytes = sum(f["size"] for v in manifest.values() for f in v["files"].values())
    print(f"listings done: {total_files} files, {total_bytes:,} bytes")

    # 2. File contents, parallel
    jobs = [(ns, path, meta)
            for ns, v in manifest.items()
            for path, meta in v["files"].items()]
    done = [0]

    def work(job):
        ns, path, meta = job
        status = fetch_file(ns, path, meta)
        with print_lock:
            done[0] += 1
            if done[0] % 100 == 0:
                print(f"  {done[0]}/{len(jobs)} files ({status})")
        return status

    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for _ in ex.map(work, jobs):
            pass

    print(f"MIRROR COMPLETE: {len(jobs)} files")


if __name__ == "__main__":
    sys.exit(main())
