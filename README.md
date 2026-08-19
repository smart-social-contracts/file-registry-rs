# file-registry-rs

Cycle-efficient on-chain file registry for [Realms](https://github.com/smart-social-contracts/realms),
written in Rust on top of [ic-certified-assets](https://github.com/smart-social-contracts/certified-assets).
A drop-in replacement for the Python `file_registry` canister: same Candid
interface, same JSON contracts, a small fraction of the cycle cost.

## Why

The original registry was Python on WASI (Basilisk). That meant:

- ~1.3 GB canister memory for ~176 MB of stored files (interpreter heap
  never shrinks) — high idle memory rent.
- `http_request` upgraded every HTTP GET to an **update call**, so every
  download paid consensus-priced execution.
- Hashing/base64 in interpreted Python cost billions of instructions per
  publish.

This implementation stores file bytes in the embedded `ic-certified-assets`
state machine, so:

- HTTP GETs are **certified query responses** — effectively free and served
  straight from the asset store with streaming for large files.
- Uploads and reads run at native Rust speed (a whole-file finalize completes
  in a single message; no incremental stepping needed).
- The canister WASM is ~370 KB gzipped instead of a multi-MB interpreter.

## Architecture

```
+--------------------------------------------------------+
| file_registry canister                                 |
|                                                        |
|  Compat JSON API (text -> text, same as Python)        |
|   store_file / store_file_chunk / finalize_* / ...     |
|   list_* / get_file* / latest_version / catalogs       |
|            |                                           |
|  Registry index (wrapper state, CBOR in stable memory) |
|   namespaces, per-file metadata, publisher ACL,        |
|   codex-curator gate, pending chunked uploads          |
|            |                                           |
|  ic-certified-assets state machine                     |
|   file bytes, certification tree, HTTP serving         |
+--------------------------------------------------------+
```

Asset keys mirror the HTTP layout: file `p` in namespace `ns` is stored at
`/{ns}/{p}`. JSON index assets are regenerated on every mutation so HTTP
reads never go stale:

- `GET /` — namespace listing
- `GET /api/extensions`, `GET /api/codices` — marketplace catalogs
- `GET /{namespace}` — file listing for one namespace
- `GET /{namespace}/{path}` — file content (certified, streamed, CORS)

## Compatibility notes

Interface and JSON shapes match the Python registry with these deliberate
deviations:

- `finalize_chunked_file_step` completes the whole assembly in its first
  call and returns `done: true` immediately (pollers just observe instant
  completion). `batch_size` is accepted and ignored.
- The stored `sha256` is always computed on-chain from the uploaded bytes.
  If a caller passes `expected_sha256` and it does not match, finalize fails
  (the Python version stored the caller's value unverified).
- `get_file_chunk` allows up to 1 MiB per read (Python capped at 128 KiB);
  callers requesting less are unaffected.
- `http_request_update` is dropped: HTTP is served as certified queries, so
  no upgrade-to-update path exists anymore.

Beyond the Python contract, this registry also stores **approvals** (below).
Existing clients are unaffected: namespaces without one simply read back as
unapproved, and `list_namespaces` gains an additive `approved` field.

## Approvals

A namespace can carry one reviewer decision, so a realm can refuse to install
content the marketplace has not approved. The registry stores the decision and
answers questions about it; it does not decide anything itself.

```
set_namespace_approval  {"namespace": "ext/foo/1.0.0",
                         "status": "approved" | "rejected",   # default approved
                         "notes":  "..."}
get_namespace_approval  {"namespace": "ext/foo/1.0.0"}
get_namespace_approval_icc(namespace)      # update, positional, for inter-canister calls
```

The read returns `approved`, `status`, `approver`, `decided_at`, `notes`,
`content_matches` and `file_count`; an unapproved namespace reads back as
`{"approved": false, "status": "unapproved"}`.

Two properties make the decision meaningful:

- **Approving is a separate right from publishing.** It needs the controller
  or a principal on the `_approvers` ACL, granted with
  `grant_publish {"namespace": "_approvers", "principal": "..."}`. Owning a
  namespace does not let you approve your own package.
- **An approval names the exact bytes reviewed.** It records the namespace's
  `path -> sha256` map, and *any* change to the namespace's content drops it —
  `store_file`, either finalize, `admin_restore_files`, `delete_file`. So
  approve-then-swap yields an unapproved namespace rather than approved
  malware. `content_matches` re-checks the hashes on every read, so a realm can
  verify the binding instead of trusting it.

Re-approval after a legitimate change is just another `set_namespace_approval`.

## Build

Requires Rust (`wasm32-unknown-unknown` target) and `ic-wasm`.

```bash
bash scripts/build.sh     # -> out/file_registry.wasm.gz
cargo test                # unit + API round-trip tests
```

## Deploy

```bash
dfx deploy file_registry            # local
# Replacing an existing (Python) registry in place, keeping the canister id:
dfx canister install file_registry --mode reinstall --network ic
```

Reinstall wipes state: republish content afterwards (the realms CI publish
pipeline does this from git).

## Test drive

```bash
dfx canister call file_registry store_file \
  '("{\"namespace\": \"wasm\", \"path\": \"hello.txt\", \"content_b64\": \"aGVsbG8=\"}")'
dfx canister call file_registry list_namespaces '()'
curl "http://$(dfx canister id file_registry).localhost:$(dfx info webserver-port)/wasm/hello.txt"
```
