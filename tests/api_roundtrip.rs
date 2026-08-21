//! Full lifecycle tests over the JSON API using the in-memory blob store.
//! These validate the exact contract the Python file_registry exposed:
//! store/publish/list/read/chunked-upload/ACL/codex-gate/purge.

use base64::Engine;
use file_registry::api::*;
use file_registry::registry::Registry;
use file_registry::store::{BlobStore, MemStore};
use serde_json::{json, Value};

fn controller() -> CallerCtx {
    CallerCtx {
        caller: "ctrl-principal".to_string(),
        is_controller: true,
        now: 1_000,
    }
}

fn user(name: &str) -> CallerCtx {
    CallerCtx {
        caller: name.to_string(),
        is_controller: false,
        now: 2_000,
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn v(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn store_small(
    reg: &mut Registry,
    store: &mut MemStore,
    ctx: &CallerCtx,
    ns: &str,
    path: &str,
    content: &[u8],
) -> Value {
    let args = json!({"namespace": ns, "path": path, "content_b64": b64(content)}).to_string();
    v(&u_store_file(reg, store, ctx, &args))
}

fn publish(reg: &mut Registry, store: &mut MemStore, ctx: &CallerCtx, ns: &str) -> Value {
    v(&u_publish_namespace(
        reg,
        store,
        ctx,
        &json!({"namespace": ns}).to_string(),
    ))
}

#[test]
fn store_and_read_roundtrip() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");

    let content: &[u8] = br#"{"name": "voting", "version": "1.0.0"}"#;
    let res = store_small(
        &mut reg,
        &mut store,
        &ctx,
        "ext/voting/1.0.0",
        "manifest.json",
        content,
    );
    assert_eq!(res["ok"], true);
    assert_eq!(res["size"], content.len());
    assert!(res["sha256"].as_str().unwrap().len() == 64);

    // get_file returns the same content and metadata
    let got = v(&q_get_file(
        &reg,
        &store,
        &json!({"namespace": "ext/voting/1.0.0", "path": "manifest.json"}).to_string(),
    ));
    assert_eq!(got["content_type"], "application/json");
    assert_eq!(got["size"], content.len());
    assert_eq!(got["sha256"], res["sha256"]);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(got["content_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, br#"{"name": "voting", "version": "1.0.0"}"#);

    // unknown file -> error, unknown namespace list -> []
    let missing = v(&q_get_file(
        &reg,
        &store,
        &json!({"namespace": "ext/voting/1.0.0", "path": "nope.py"}).to_string(),
    ));
    assert!(missing["error"].as_str().unwrap().contains("Not found"));
    assert_eq!(
        q_list_files(&reg, &json!({"namespace": "no/such"}).to_string()),
        "[]"
    );

    // list_files shape
    let files = v(&q_list_files(
        &reg,
        &json!({"namespace": "ext/voting/1.0.0"}).to_string(),
    ));
    assert_eq!(files.as_array().unwrap().len(), 1);
    assert_eq!(files[0]["path"], "manifest.json");
    assert_eq!(files[0]["content_type"], "application/json");

    // stats
    let stats = v(&q_get_stats(&reg));
    assert_eq!(stats["namespaces"], 1);
    assert_eq!(stats["total_files"], 1);
    assert_eq!(stats["total_bytes"], content.len());
}

#[test]
fn acl_auto_grant_and_enforcement() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();

    // First non-controller caller is auto-granted.
    let res = store_small(
        &mut reg,
        &mut store,
        &user("alice"),
        "ext/gov/1.0.0",
        "a.py",
        b"x = 1",
    );
    assert_eq!(res["ok"], true);

    // A different caller is rejected.
    let res = store_small(
        &mut reg,
        &mut store,
        &user("bob"),
        "ext/gov/1.0.0",
        "b.py",
        b"x = 2",
    );
    assert!(res["error"].as_str().unwrap().contains("not a publisher"));

    // Controller always allowed.
    let res = store_small(
        &mut reg,
        &mut store,
        &controller(),
        "ext/gov/1.0.0",
        "c.py",
        b"x = 3",
    );
    assert_eq!(res["ok"], true);

    // Controller can grant bob, then bob can publish.
    let res = v(&u_grant_publish(
        &mut reg,
        &controller(),
        &json!({"namespace": "ext/gov/1.0.0", "principal": "bob"}).to_string(),
    ));
    assert_eq!(res["ok"], true);
    let res = store_small(
        &mut reg,
        &mut store,
        &user("bob"),
        "ext/gov/1.0.0",
        "b.py",
        b"x = 2",
    );
    assert_eq!(res["ok"], true);

    // Revoke removes access again.
    v(&u_revoke_publish(
        &mut reg,
        &controller(),
        &json!({"namespace": "ext/gov/1.0.0", "principal": "bob"}).to_string(),
    ));
    let res = store_small(
        &mut reg,
        &mut store,
        &user("bob"),
        "ext/gov/1.0.0",
        "d.py",
        b"x = 4",
    );
    assert!(res["error"].as_str().unwrap().contains("not a publisher"));

    // ACL is visible.
    let acl = v(&q_get_acl(&reg));
    assert_eq!(acl["ext/gov/1.0.0"], json!(["alice"]));
}

#[test]
fn codex_gate_blocks_uncurated() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();

    // Manifest claiming kind: codex from an uncurated user is rejected.
    let res = store_small(
        &mut reg,
        &mut store,
        &user("mallory"),
        "ext/evil/1.0.0",
        "manifest.json",
        br#"{"kind": "codex"}"#,
    );
    assert!(res["error"].as_str().unwrap().contains("codex-curator"));

    // Legacy codex/ namespace also gated.
    let res = store_small(
        &mut reg,
        &mut store,
        &user("mallory"),
        "codex/evil/1.0.0",
        "entry.py",
        b"pass",
    );
    assert!(res["error"].as_str().unwrap().contains("codex-curator"));

    // Controller can appoint a curator, who is then allowed.
    v(&u_grant_publish(
        &mut reg,
        &controller(),
        &json!({"namespace": "_codex_curators", "principal": "carol"}).to_string(),
    ));
    let res = store_small(
        &mut reg,
        &mut store,
        &user("carol"),
        "ext/good/1.0.0",
        "manifest.json",
        br#"{"kind": "codex", "name": "good"}"#,
    );
    assert_eq!(res["ok"], true);

    // Non-codex manifests pass without curation.
    let res = store_small(
        &mut reg,
        &mut store,
        &user("dave"),
        "ext/plain/1.0.0",
        "manifest.json",
        br#"{"kind": "extension"}"#,
    );
    assert_eq!(res["ok"], true);
}

#[test]
fn empty_wasm_rejected() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");

    for path in ["realm-base-1.0.0.wasm", "realm-base-1.0.0.WASM", "pkg/module.Wasm"] {
        let res = store_small(&mut reg, &mut store, &ctx, "wasm", path, b"");
        assert_eq!(res["error"], "empty wasm not allowed", "path={path}");
    }

    // Empty non-wasm files are still allowed.
    let res = store_small(&mut reg, &mut store, &ctx, "wasm", "empty.bin", b"");
    assert_eq!(res["ok"], true);
    assert_eq!(res["size"], 0);
}

#[test]
fn chunked_upload_and_range_reads() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");
    let ns = "wasm";
    let path = "realm-base-1.2.3.wasm";

    // 3 chunks, uploaded out of order.
    let part_a = vec![1u8; 1000];
    let part_b = vec![2u8; 1000];
    let part_c = vec![3u8; 500];
    for (i, data) in [(1u32, &part_b), (0, &part_a), (2, &part_c)] {
        let res = v(&u_store_file_chunk(
            &mut reg,
            &ctx,
            &json!({"namespace": ns, "path": path, "chunk_index": i,
                     "total_chunks": 3, "data_b64": b64(data)})
            .to_string(),
        ));
        assert_eq!(res["ok"], true, "chunk {i}: {res}");
    }

    let full: Vec<u8> = [part_a.clone(), part_b.clone(), part_c.clone()].concat();
    let sha = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&full))
    };

    // finalize_chunked_file_step completes in one call with the right hash.
    let res = v(&u_finalize_chunked_file_step(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": ns, "path": path, "expected_sha256": sha, "batch_size": 1})
            .to_string(),
    ));
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["done"], true);
    assert_eq!(res["processed"], 3);
    assert_eq!(res["total"], 3);
    assert_eq!(res["size"], 2500);
    assert_eq!(res["sha256"].as_str().unwrap(), sha);

    // Ranged chunk read
    let res = v(&get_file_chunk_impl(&store, ns, path, 900, 200));
    assert_eq!(res["offset"], 900);
    assert_eq!(res["length"], 200);
    assert_eq!(res["total_size"], 2500);
    assert_eq!(res["eof"], false);
    let slice = base64::engine::general_purpose::STANDARD
        .decode(res["content_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(&slice[..100], &full[900..1000]);
    assert_eq!(&slice[100..], &full[1000..1100]);

    // Read to eof
    let res = v(&get_file_chunk_impl(&store, ns, path, 2400, 1000));
    assert_eq!(res["length"], 100);
    assert_eq!(res["eof"], true);

    // Out-of-range offset
    let res = v(&get_file_chunk_impl(&store, ns, path, 3000, 10));
    assert!(res["error"].as_str().unwrap().contains("out of range"));

    // get_file_size sees it
    let res = v(&q_get_file_size(
        &reg,
        &store,
        &json!({"namespace": ns, "path": path}).to_string(),
    ));
    assert_eq!(res["size"], 2500);
    assert_eq!(res["sha256"].as_str().unwrap(), sha);
}

#[test]
fn chunked_upload_sha_mismatch_keeps_pending() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");
    let args = json!({"namespace": "wasm", "path": "f.bin", "chunk_index": 0,
                      "total_chunks": 1, "data_b64": b64(b"hello")})
    .to_string();
    v(&u_store_file_chunk(&mut reg, &ctx, &args));

    let res = v(&u_finalize_chunked_file_step(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "wasm", "path": "f.bin",
                 "expected_sha256": "deadbeef"})
        .to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("sha256 mismatch"));

    // Pending upload survived; finalize without hash succeeds.
    let res = v(&u_finalize_chunked_file(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "wasm", "path": "f.bin"}).to_string(),
    ));
    assert_eq!(res["ok"], true, "{res}");
}

#[test]
fn missing_chunk_reported() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");
    v(&u_store_file_chunk(
        &mut reg,
        &ctx,
        &json!({"namespace": "wasm", "path": "g.bin", "chunk_index": 0,
                 "total_chunks": 3, "data_b64": b64(b"a")})
        .to_string(),
    ));
    v(&u_store_file_chunk(
        &mut reg,
        &ctx,
        &json!({"namespace": "wasm", "path": "g.bin", "chunk_index": 2,
                 "total_chunks": 3, "data_b64": b64(b"c")})
        .to_string(),
    ));
    let res = v(&u_finalize_chunked_file(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "wasm", "path": "g.bin"}).to_string(),
    ));
    assert_eq!(res["error"], "Missing chunk 1 of 3");
}

#[test]
fn catalogs_and_version_resolution() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");

    for ver in ["1.0.0", "1.1.0", "2.0.0"] {
        let ns = format!("ext/voting/{ver}");
        store_small(
            &mut reg,
            &mut store,
            &ctx,
            &ns,
            "manifest.json",
            format!(r#"{{"name": "voting", "version": "{ver}"}}"#).as_bytes(),
        );
        store_small(
            &mut reg,
            &mut store,
            &ctx,
            &ns,
            "backend/entry.py",
            b"def run(): pass",
        );
        store_small(
            &mut reg,
            &mut store,
            &ctx,
            &ns,
            "frontend/index.js",
            b"export {}",
        );
    }
    // 2.0.0 stays unpublished (partial upload)
    publish(&mut reg, &mut store, &ctx, "ext/voting/1.0.0");
    publish(&mut reg, &mut store, &ctx, "ext/voting/1.1.0");

    // A codex package via the unified ext/ pipeline (curated caller).
    v(&u_grant_publish(
        &mut reg,
        &controller(),
        &json!({"namespace": "_codex_curators", "principal": "carol"}).to_string(),
    ));
    store_small(
        &mut reg,
        &mut store,
        &user("carol"),
        "ext/syntropia/0.8.7",
        "manifest.json",
        br#"{"kind": "codex", "name": "syntropia"}"#,
    );
    store_small(
        &mut reg,
        &mut store,
        &user("carol"),
        "ext/syntropia/0.8.7",
        "entry.py",
        b"# codex",
    );
    publish(&mut reg, &mut store, &user("carol"), "ext/syntropia/0.8.7");

    // list_extensions: unpublished 2.0.0 hidden, manifest embedded from latest.
    let exts = v(&list_extensions_json(&reg, &store));
    let voting = exts
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["ext_id"] == "voting")
        .unwrap();
    assert_eq!(voting["versions"], json!(["1.0.0", "1.1.0"]));
    assert_eq!(voting["latest"], "1.1.0");
    assert_eq!(voting["manifest"]["version"], "1.1.0");

    // list_codices finds the ext/-pipeline codex.
    let codices = v(&list_codices_json(&reg, &store));
    let syn = codices
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["codex_id"] == "syntropia")
        .unwrap();
    assert_eq!(syn["latest"], "0.8.7");
    assert_eq!(syn["namespace_prefix"], "ext");

    // latest_version endpoint
    let res = v(&q_latest_version(
        &reg,
        &json!({"category": "ext", "item_id": "voting"}).to_string(),
    ));
    assert_eq!(res["latest"], "1.1.0");
    assert_eq!(res["namespace"], "ext/voting/1.1.0");

    // get_extension_manifest with explicit + latest resolution
    let res = v(&q_get_extension_manifest(
        &reg,
        &store,
        &json!({"ext_id": "voting", "version": "1.0.0"}).to_string(),
    ));
    assert_eq!(res["version"], "1.0.0");
    assert_eq!(res["_namespace"], "ext/voting/1.0.0");
    let res = v(&q_get_extension_manifest(
        &reg,
        &store,
        &json!({"ext_id": "voting"}).to_string(),
    ));
    assert_eq!(res["_version"], "1.1.0");

    // get_backend_files: latest, pinned, and range spec
    let res = v(&get_backend_files_impl(&reg, &store, "ext", "voting", ""));
    assert_eq!(res["version"], "1.1.0");
    assert_eq!(res["file_count"], 2);
    assert!(res["files"]["backend/entry.py"]
        .as_str()
        .unwrap()
        .contains("def run"));
    assert!(res["files"].get("frontend/index.js").is_none());

    let res = v(&get_backend_files_impl(
        &reg, &store, "ext", "voting", "1.0.0",
    ));
    assert_eq!(res["version"], "1.0.0");

    let res = v(&get_backend_files_impl(
        &reg, &store, "ext", "voting", "1.x",
    ));
    assert_eq!(res["version"], "1.1.0");

    let res = v(&get_backend_files_impl(
        &reg, &store, "ext", "voting", "^1.0.0",
    ));
    assert_eq!(res["version"], "1.1.0");

    // Unpublished exact pin is refused.
    let res = v(&get_backend_files_impl(
        &reg, &store, "ext", "voting", "2.0.0",
    ));
    assert!(res["error"].as_str().unwrap().contains("not yet published"));

    // No match
    let res = v(&get_backend_files_impl(
        &reg, &store, "ext", "voting", "3.x",
    ));
    assert!(res["error"].as_str().unwrap().contains("matches '3.x'"));

    // get_frontend_files
    let res = v(&get_frontend_files_impl(&reg, &store, "voting", ""));
    assert_eq!(res["file_count"], 1);
    assert!(res["files"]["frontend/index.js"]
        .as_str()
        .unwrap()
        .contains("export"));
}

#[test]
fn http_index_assets_stay_fresh() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");

    store_small(
        &mut reg,
        &mut store,
        &ctx,
        "ext/gov/1.0.0",
        "manifest.json",
        br#"{"a":1}"#,
    );
    publish(&mut reg, &mut store, &ctx, "ext/gov/1.0.0");

    // Root listing regenerated as an asset at "/".
    let root: Value = serde_json::from_slice(&store.read("/").unwrap()).unwrap();
    assert_eq!(root[0]["namespace"], "ext/gov/1.0.0");
    assert_eq!(root[0]["file_count"], 1);

    // Namespace listing at "/{ns}".
    let listing: Value = serde_json::from_slice(&store.read("/ext/gov/1.0.0").unwrap()).unwrap();
    assert_eq!(listing[0]["path"], "manifest.json");

    // Catalog at /api/extensions includes the published version.
    let exts: Value = serde_json::from_slice(&store.read("/api/extensions").unwrap()).unwrap();
    assert_eq!(exts[0]["ext_id"], "gov");

    // The file itself is HTTP-addressable.
    assert_eq!(
        store.read("/ext/gov/1.0.0/manifest.json").unwrap(),
        br#"{"a":1}"#
    );

    // Deleting the namespace removes file + listing assets and refreshes root.
    v(&u_delete_namespace(
        &mut reg,
        &mut store,
        &controller(),
        &json!({"namespace": "ext/gov/1.0.0"}).to_string(),
    ));
    assert!(store.read("/ext/gov/1.0.0/manifest.json").is_none());
    assert!(store.read("/ext/gov/1.0.0").is_none());
    let root: Value = serde_json::from_slice(&store.read("/").unwrap()).unwrap();
    assert_eq!(root.as_array().unwrap().len(), 0);
}

#[test]
fn delete_file_and_namespace_auth() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");
    store_small(&mut reg, &mut store, &ctx, "ext/gov/1.0.0", "a.py", b"x");

    // delete_namespace is controller-only.
    let res = v(&u_delete_namespace(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "ext/gov/1.0.0"}).to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("not a controller"));

    // delete_file by publisher works; second delete errors.
    let res = v(&u_delete_file(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "ext/gov/1.0.0", "path": "a.py"}).to_string(),
    ));
    assert_eq!(res["ok"], true);
    let res = v(&u_delete_file(
        &mut reg,
        &mut store,
        &ctx,
        &json!({"namespace": "ext/gov/1.0.0", "path": "a.py"}).to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("Not found"));
}

#[test]
fn purge_old_versions_lifecycle() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    let ctx = user("alice");

    for ver in ["1.0.0", "1.1.0", "1.2.0", "2.0.0"] {
        let ns = format!("ext/gov/{ver}");
        store_small(
            &mut reg,
            &mut store,
            &ctx,
            &ns,
            "manifest.json",
            br#"{"a":1}"#,
        );
        publish(&mut reg, &mut store, &ctx, &ns);
    }
    // An unpublished (abandoned) version is always purged.
    store_small(
        &mut reg,
        &mut store,
        &ctx,
        "ext/gov/0.9.0",
        "manifest.json",
        br#"{"a":1}"#,
    );

    // WASM namespace with three versions of the base build.
    for ver in ["1.0.0", "1.1.0", "1.2.0"] {
        store_small(
            &mut reg,
            &mut store,
            &ctx,
            "wasm",
            &format!("realm-base-{ver}.wasm.gz"),
            b"wasmbytes",
        );
    }
    store_small(&mut reg, &mut store, &ctx, "wasm", "other.bin", b"keepme");

    // Non-controller refused.
    let res = v(&u_purge_old_versions(&mut reg, &mut store, &ctx, "{}"));
    assert!(res["error"].as_str().unwrap().contains("not a controller"));

    // Dry run (default): reports, deletes nothing.
    let res = v(&u_purge_old_versions(
        &mut reg,
        &mut store,
        &controller(),
        "{}",
    ));
    assert_eq!(res["dry_run"], true);
    let deleted: Vec<&str> = res["deleted_namespaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["namespace"].as_str().unwrap())
        .collect();
    assert!(deleted.contains(&"ext/gov/1.0.0"));
    assert!(deleted.contains(&"ext/gov/1.1.0"));
    assert!(deleted.contains(&"ext/gov/0.9.0"));
    assert_eq!(reg.namespaces.len(), 6); // nothing actually deleted

    // Real purge keeping 2.
    let res = v(&u_purge_old_versions(
        &mut reg,
        &mut store,
        &controller(),
        &json!({"keep": 2, "dry_run": false}).to_string(),
    ));
    assert_eq!(res["dry_run"], false);
    assert!(reg.namespaces.contains_key("ext/gov/2.0.0"));
    assert!(reg.namespaces.contains_key("ext/gov/1.2.0"));
    assert!(!reg.namespaces.contains_key("ext/gov/1.1.0"));
    assert!(!reg.namespaces.contains_key("ext/gov/0.9.0"));
    // wasm: keeps 2 newest realm-base gz + the unrelated file
    let kept_wasm: Vec<&str> = res["kept_wasm_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(
        kept_wasm,
        vec![
            "other.bin",
            "realm-base-1.1.0.wasm.gz",
            "realm-base-1.2.0.wasm.gz"
        ]
    );
    assert!(store.read("/wasm/realm-base-1.0.0.wasm.gz").is_none());
    assert!(store.read("/wasm/realm-base-1.1.0.wasm.gz").is_some());
    // Purged namespace assets are gone.
    assert!(store.read("/ext/gov/1.0.0/manifest.json").is_none());
}

#[test]
fn admin_restore_bulk() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();

    // Non-controller refused.
    let res = v(&u_admin_restore_files(
        &mut reg,
        &mut store,
        &user("alice"),
        &json!({"namespace": "ext/x/1.0.0", "files": []}).to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("not a controller"));

    // Controller restores two files with preserved metadata + publish flag.
    use sha2::Digest;
    let sha_a = hex::encode(sha2::Sha256::digest(b"content a"));
    let args = json!({
        "namespace": "ext/x/1.0.0",
        "publish": true,
        "description": "restored",
        "files": [
            {"path": "manifest.json", "content_b64": b64(br#"{"name":"x"}"#),
             "content_type": "application/json", "updated": 12345},
            {"path": "backend/a.py", "content_b64": b64(b"content a"), "sha256": sha_a},
        ],
    })
    .to_string();
    let res = v(&u_admin_restore_files(
        &mut reg,
        &mut store,
        &controller(),
        &args,
    ));
    assert_eq!(res["ok"], true, "{res}");
    assert_eq!(res["restored"], 2);

    // Metadata round-trips (original updated timestamp preserved).
    let files = v(&q_list_files(
        &reg,
        &json!({"namespace": "ext/x/1.0.0"}).to_string(),
    ));
    let manifest = files
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "manifest.json")
        .unwrap();
    assert_eq!(manifest["updated"], 12345);

    // Published and visible in catalogs, content readable.
    let exts = v(&list_extensions_json(&reg, &store));
    assert_eq!(exts[0]["ext_id"], "x");
    assert_eq!(
        store.read("/ext/x/1.0.0/backend/a.py").unwrap(),
        b"content a"
    );

    // sha mismatch rejected.
    let res = v(&u_admin_restore_files(
        &mut reg,
        &mut store,
        &controller(),
        &json!({"namespace": "ext/x/1.0.0", "files": [
            {"path": "bad.bin", "content_b64": b64(b"zzz"), "sha256": "00"}
        ]})
        .to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("sha256 mismatch"));
}

#[test]
fn update_namespace_description() {
    let mut reg = Registry::default();
    let mut store = MemStore::default();
    store_small(&mut reg, &mut store, &user("alice"), "wasm", "a.bin", b"x");

    let res = v(&u_update_namespace(
        &mut reg,
        &mut store,
        &controller(),
        &json!({"namespace": "wasm", "description": "base wasm builds"}).to_string(),
    ));
    assert_eq!(res["ok"], true);
    let listing = v(&list_namespaces_json(&reg));
    assert_eq!(listing[0]["description"], "base wasm builds");

    let res = v(&u_update_namespace(
        &mut reg,
        &mut store,
        &controller(),
        &json!({"namespace": "nope"}).to_string(),
    ));
    assert!(res["error"].as_str().unwrap().contains("not found"));
}
