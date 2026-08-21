//! Endpoint implementations. All functions are pure with respect to the IC:
//! caller identity and time come in via [`CallerCtx`], bytes go through the
//! [`BlobStore`] trait — so everything here is unit-testable off-chain.
//!
//! Every function returns a JSON string matching the Python file_registry
//! contract: results on success, `{"error": "..."}` on failure, never traps.

use crate::registry::{
    find_latest_version, guess_content_type, parse_semver, pending_key, resolve_version_spec,
    FileMeta, PendingUpload, Registry, CODEX_CURATORS_ACL_KEY, NS_PREFIX_CODEX, NS_PREFIX_EXT,
    NS_PREFIX_WASM,
};
use crate::store::{asset_key, BlobStore};
use base64::Engine;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::BTreeMap;

/// Per-chunk read cap for `get_file_chunk`. The Python registry capped at
/// 128 KiB because base64 in WASI Python was expensive; in Rust we can afford
/// 1 MiB per call (b64 ≈ 1.37 MiB, safely under the 2 MiB message limit).
/// Callers that request less are unaffected.
pub const MAX_CHUNK_READ_BYTES: u64 = 1024 * 1024;

pub struct CallerCtx {
    pub caller: String,
    pub is_controller: bool,
    pub now: u64,
}

fn err(msg: impl std::fmt::Display) -> String {
    json!({"error": msg.to_string()}).to_string()
}

fn parse_args(args: &str) -> Result<Value, String> {
    if args.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str::<Value>(args).map_err(|e| format!("invalid args (not JSON): {e}"))
}

fn str_field<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing or invalid field '{key}'"))
}

fn sha256_hex(chunks: &[impl AsRef<[u8]>]) -> String {
    let mut h = sha2::Sha256::new();
    for c in chunks {
        h.update(c.as_ref());
    }
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

fn require_controller(ctx: &CallerCtx) -> Option<String> {
    if !ctx.is_controller {
        return Some(err("Unauthorized: caller is not a controller"));
    }
    None
}

/// Controller or namespace publisher; first caller to an ACL-less namespace
/// is auto-granted (same as the Python registry).
fn require_publisher(reg: &mut Registry, ctx: &CallerCtx, namespace: &str) -> Option<String> {
    if ctx.is_controller {
        return None;
    }
    let ns_acl = reg.acl.entry(namespace.to_string()).or_default();
    if ns_acl.iter().any(|p| p == &ctx.caller) {
        return None;
    }
    if ns_acl.is_empty() {
        ns_acl.push(ctx.caller.clone());
        return None;
    }
    Some(err(format!(
        "Unauthorized: not a publisher for namespace '{namespace}'"
    )))
}

fn require_codex_curator(reg: &Registry, ctx: &CallerCtx) -> Option<String> {
    if ctx.is_controller {
        return None;
    }
    if reg
        .acl
        .get(CODEX_CURATORS_ACL_KEY)
        .map(|l| l.iter().any(|p| p == &ctx.caller))
        .unwrap_or(false)
    {
        return None;
    }
    Some(err(
        "Unauthorized: publishing a codex package (kind: codex) requires \
         codex-curator rights on this registry",
    ))
}

/// Reject uncurated uploads that claim the privileged codex classification:
/// any manifest.json declaring `"kind": "codex"`, and all writes under the
/// legacy `codex/` namespace.
fn codex_manifest_gate(
    reg: &Registry,
    ctx: &CallerCtx,
    namespace: &str,
    path: &str,
    content: &[u8],
) -> Option<String> {
    if namespace.starts_with(NS_PREFIX_CODEX) {
        return require_codex_curator(reg, ctx);
    }
    if path.rsplit('/').next() != Some("manifest.json") {
        return None;
    }
    let Ok(manifest) = serde_json::from_slice::<Value>(content) else {
        return None;
    };
    if manifest.get("kind").and_then(|k| k.as_str()) == Some("codex") {
        return require_codex_curator(reg, ctx);
    }
    None
}

// ---------------------------------------------------------------------------
// Listings (shared between the Candid queries and the HTTP index assets)
// ---------------------------------------------------------------------------

pub fn list_namespaces_json(reg: &Registry) -> String {
    let mut result = Vec::new();
    for (ns_name, ns_info) in &reg.namespaces {
        let empty = BTreeMap::new();
        let files = reg.ns_files(ns_name).unwrap_or(&empty);
        let total_bytes: u64 = files.values().map(|f| f.size).sum();
        result.push(json!({
            "namespace": ns_name,
            "file_count": files.len(),
            "total_bytes": total_bytes,
            "created": ns_info.created,
            "owner": ns_info.owner,
            "description": ns_info.description,
        }));
    }
    // BTreeMap iteration is already sorted by namespace.
    serde_json::to_string(&result).unwrap()
}

pub fn list_files_json(reg: &Registry, namespace: &str) -> String {
    if !reg.namespaces.contains_key(namespace) {
        return "[]".to_string();
    }
    let empty = BTreeMap::new();
    let files = reg.ns_files(namespace).unwrap_or(&empty);
    let result: Vec<Value> = files
        .iter()
        .map(|(path, info)| {
            json!({
                "path": path,
                "size": info.size,
                "content_type": info.content_type,
                "sha256": info.sha256,
                "updated": info.updated,
            })
        })
        .collect();
    serde_json::to_string(&result).unwrap()
}

pub fn q_list_files(reg: &Registry, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let Some(namespace) = params.get("namespace").and_then(|v| v.as_str()) else {
        return err("expected JSON object with 'namespace' field");
    };
    list_files_json(reg, namespace)
}

pub fn q_get_stats(reg: &Registry) -> String {
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    for ns_name in reg.namespaces.keys() {
        if let Some(files) = reg.ns_files(ns_name) {
            total_files += files.len();
            total_bytes += files.values().map(|f| f.size).sum::<u64>();
        }
    }
    json!({
        "namespaces": reg.namespaces.len(),
        "total_files": total_files,
        "total_bytes": total_bytes,
    })
    .to_string()
}

pub fn q_get_acl(reg: &Registry) -> String {
    serde_json::to_string(&reg.acl).unwrap()
}

// ---------------------------------------------------------------------------
// File reads
// ---------------------------------------------------------------------------

fn file_meta<'a>(reg: &'a Registry, namespace: &str, path: &str) -> Option<&'a FileMeta> {
    reg.ns_files(namespace).and_then(|files| files.get(path))
}

pub fn q_get_file(reg: &Registry, store: &dyn BlobStore, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/'),
        Err(e) => return err(e),
    };
    let Some(content) = store.read(&asset_key(namespace, path)) else {
        return err(format!("Not found: {namespace}/{path}"));
    };
    let meta = file_meta(reg, namespace, path);
    let content_type = meta
        .map(|m| m.content_type.clone())
        .filter(|ct| !ct.is_empty())
        .unwrap_or_else(|| guess_content_type(path));
    let sha256 = meta
        .map(|m| m.sha256.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| sha256_hex(&[&content]));
    json!({
        "content_b64": base64::engine::general_purpose::STANDARD.encode(&content),
        "content_type": content_type,
        "size": content.len(),
        "sha256": sha256,
    })
    .to_string()
}

fn get_file_size_impl(
    reg: &Registry,
    store: &dyn BlobStore,
    namespace: &str,
    path: &str,
) -> String {
    let path = path.trim_start_matches('/');
    let Some((_, total)) = store.read_range(&asset_key(namespace, path), 0, 0) else {
        return err(format!("Not found: {namespace}/{path}"));
    };
    let meta = file_meta(reg, namespace, path);
    json!({
        "size": total,
        "content_type": meta
            .map(|m| m.content_type.clone())
            .filter(|ct| !ct.is_empty())
            .unwrap_or_else(|| guess_content_type(path)),
        "sha256": meta.map(|m| m.sha256.clone()).unwrap_or_default(),
    })
    .to_string()
}

pub fn q_get_file_size(reg: &Registry, store: &dyn BlobStore, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    get_file_size_impl(reg, store, namespace, path)
}

pub fn get_file_chunk_impl(
    store: &dyn BlobStore,
    namespace: &str,
    path: &str,
    offset: i64,
    length: i64,
) -> String {
    let path = path.trim_start_matches('/');
    let length = if length <= 0 || length as u64 > MAX_CHUNK_READ_BYTES {
        MAX_CHUNK_READ_BYTES
    } else {
        length as u64
    };
    let key = asset_key(namespace, path);
    let Some((_, size)) = store.read_range(&key, 0, 0) else {
        return err(format!("Not found: {namespace}/{path}"));
    };
    if offset < 0 || offset as u64 > size {
        return err(format!("Offset {offset} out of range (size={size})"));
    }
    let offset = offset as u64;
    let Some((chunk, total)) = store.read_range(&key, offset, length) else {
        return err(format!("Not found: {namespace}/{path}"));
    };
    json!({
        "content_b64": base64::engine::general_purpose::STANDARD.encode(&chunk),
        "offset": offset,
        "length": chunk.len(),
        "total_size": total,
        "eof": offset + chunk.len() as u64 >= total,
    })
    .to_string()
}

pub fn q_get_file_chunk(store: &dyn BlobStore, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let offset = params.get("offset").and_then(|v| v.as_i64()).unwrap_or(0);
    let length = params
        .get("length")
        .and_then(|v| v.as_i64())
        .unwrap_or(MAX_CHUNK_READ_BYTES as i64);
    get_file_chunk_impl(store, &namespace, &path, offset, length)
}

// ---------------------------------------------------------------------------
// Convention-aware queries (extensions / codices / manifests / bundles)
// ---------------------------------------------------------------------------

fn read_manifest(store: &dyn BlobStore, ns: &str) -> Option<Value> {
    let bytes = store.read(&asset_key(ns, "manifest.json"))?;
    serde_json::from_slice::<Value>(&bytes).ok()
}

fn manifest_declares_codex(store: &dyn BlobStore, ns: &str) -> bool {
    read_manifest(store, ns)
        .map(|m| m.get("kind").and_then(|k| k.as_str()) == Some("codex"))
        .unwrap_or(false)
}

pub fn list_extensions_json(reg: &Registry, store: &dyn BlobStore) -> String {
    let mut extensions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (ns_name, ns_info) in &reg.namespaces {
        if !ns_name.starts_with(NS_PREFIX_EXT) || !ns_info.published {
            continue;
        }
        let rest = &ns_name[NS_PREFIX_EXT.len()..];
        let Some((ext_id, version)) = rest.split_once('/') else {
            continue;
        };
        extensions
            .entry(ext_id.to_string())
            .or_default()
            .push(version.to_string());
    }

    let mut result = Vec::new();
    for (ext_id, mut versions) in extensions {
        versions.sort_by_key(|v| parse_semver(v));
        let latest = versions.last().cloned().unwrap_or_default();
        let manifest = if latest.is_empty() {
            Value::Null
        } else {
            read_manifest(store, &format!("{NS_PREFIX_EXT}{ext_id}/{latest}"))
                .unwrap_or(Value::Null)
        };
        result.push(json!({
            "ext_id": ext_id,
            "versions": versions,
            "latest": latest,
            "manifest": manifest,
        }));
    }
    serde_json::to_string(&result).unwrap()
}

pub fn list_codices_json(reg: &Registry, store: &dyn BlobStore) -> String {
    struct Entry {
        versions: Vec<String>,
        prefixes: BTreeMap<String, &'static str>,
    }
    let mut codices: BTreeMap<String, Entry> = BTreeMap::new();

    for (ns_name, ns_info) in &reg.namespaces {
        if !ns_info.published {
            continue;
        }
        let (prefix, rest) = if let Some(rest) = ns_name.strip_prefix(NS_PREFIX_CODEX) {
            ("codex", rest)
        } else if let Some(rest) = ns_name.strip_prefix(NS_PREFIX_EXT) {
            if !manifest_declares_codex(store, ns_name) {
                continue;
            }
            ("ext", rest)
        } else {
            continue;
        };
        let Some((codex_id, version)) = rest.split_once('/') else {
            continue;
        };
        let entry = codices.entry(codex_id.to_string()).or_insert(Entry {
            versions: Vec::new(),
            prefixes: BTreeMap::new(),
        });
        entry.versions.push(version.to_string());
        entry.prefixes.insert(version.to_string(), prefix);
    }

    let mut result = Vec::new();
    for (codex_id, mut entry) in codices {
        entry.versions.sort_by_key(|v| parse_semver(v));
        let latest = entry.versions.last().cloned().unwrap_or_default();
        let namespace_prefix = entry.prefixes.get(&latest).copied().unwrap_or("codex");
        result.push(json!({
            "codex_id": codex_id,
            "versions": entry.versions,
            "latest": latest,
            "namespace_prefix": namespace_prefix,
        }));
    }
    serde_json::to_string(&result).unwrap()
}

pub fn q_latest_version(reg: &Registry, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let category = match str_field(&params, "category") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let item_id = match str_field(&params, "item_id") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let prefix = match category {
        "ext" => format!("{NS_PREFIX_EXT}{item_id}/"),
        "codex" => format!("{NS_PREFIX_CODEX}{item_id}/"),
        other => return err(format!("Unknown category: {other}. Use 'ext' or 'codex'")),
    };
    let version = find_latest_version(&reg.namespaces, &prefix);
    if version.is_empty() {
        return err(format!("No versions found for {category}/{item_id}"));
    }
    json!({
        "latest": version,
        "namespace": format!("{prefix}{version}").trim_end_matches('/'),
    })
    .to_string()
}

pub fn q_get_extension_manifest(reg: &Registry, store: &dyn BlobStore, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let ext_id = match str_field(&params, "ext_id") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let mut version = params
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if version.eq_ignore_ascii_case("latest") {
        version = String::new();
    }
    if version.is_empty() {
        let prefix = format!("{NS_PREFIX_EXT}{ext_id}/");
        version = find_latest_version(&reg.namespaces, &prefix);
        if version.is_empty() {
            return err(format!("No versions found for extension '{ext_id}'"));
        }
    }
    let ns = format!("{NS_PREFIX_EXT}{ext_id}/{version}");
    let Some(bytes) = store.read(&asset_key(&ns, "manifest.json")) else {
        return err(format!("manifest.json not found in {ns}"));
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(mut manifest)) => {
            manifest.insert("_version".to_string(), json!(version));
            manifest.insert("_namespace".to_string(), json!(ns));
            Value::Object(manifest).to_string()
        }
        Ok(other) => other.to_string(),
        Err(_) => err(format!("Invalid JSON in manifest.json for {ns}")),
    }
}

fn read_text_files(
    reg: &Registry,
    store: &dyn BlobStore,
    ns: &str,
    filter: impl Fn(&str) -> bool,
) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    if let Some(metas) = reg.ns_files(ns) {
        for path in metas.keys() {
            if filter(path) {
                if let Some(bytes) = store.read(&asset_key(ns, path)) {
                    files.insert(path.clone(), String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
    }
    files
}

pub fn get_backend_files_impl(
    reg: &Registry,
    store: &dyn BlobStore,
    category: &str,
    item_id: &str,
    version: &str,
) -> String {
    let prefix = match category {
        "ext" => format!("{NS_PREFIX_EXT}{item_id}/"),
        "codex" => format!("{NS_PREFIX_CODEX}{item_id}/"),
        other => return err(format!("Unknown category: {other}")),
    };
    let resolved = resolve_version_spec(&reg.namespaces, &prefix, version);
    if resolved.is_empty() {
        let spec = if version.is_empty() {
            "latest"
        } else {
            version
        };
        return err(format!(
            "No published version of {category}/{item_id} matches '{spec}'"
        ));
    }
    let ns = format!("{prefix}{resolved}");
    let ns = ns.trim_end_matches('/').to_string();

    let Some(ns_info) = reg.namespaces.get(&ns) else {
        return err(format!("Namespace '{ns}' not found"));
    };
    if !ns_info.published {
        return err(format!("Namespace '{ns}' is not yet published"));
    }

    let files = match category {
        "ext" => read_text_files(reg, store, &ns, |p| {
            p.starts_with("backend/") || p == "manifest.json"
        }),
        _ => read_text_files(reg, store, &ns, |_| true),
    };
    json!({
        "files": files,
        "version": resolved,
        "namespace": ns,
        "file_count": files.len(),
    })
    .to_string()
}

pub fn get_frontend_files_impl(
    reg: &Registry,
    store: &dyn BlobStore,
    item_id: &str,
    version: &str,
) -> String {
    let prefix = format!("{NS_PREFIX_EXT}{item_id}/");
    let mut version = version.trim().to_string();
    if version.eq_ignore_ascii_case("latest") {
        version = String::new();
    }
    if version.is_empty() {
        version = find_latest_version(&reg.namespaces, &prefix);
        if version.is_empty() {
            return err(format!("No versions found for ext/{item_id}"));
        }
    }
    let ns = format!("{prefix}{version}");
    let ns = ns.trim_end_matches('/').to_string();
    let Some(ns_info) = reg.namespaces.get(&ns) else {
        return err(format!("Namespace '{ns}' not found"));
    };
    if !ns_info.published {
        return err(format!("Namespace '{ns}' is not yet published"));
    }
    let files = read_text_files(reg, store, &ns, |p| p.starts_with("frontend/"));
    json!({
        "files": files,
        "version": version,
        "namespace": ns,
        "file_count": files.len(),
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// HTTP index assets
// ---------------------------------------------------------------------------

/// Regenerate the JSON index assets served over HTTP: the root namespace
/// listing at "/", the marketplace catalogs at /api/extensions and
/// /api/codices, and (when given) one namespace's file listing at "/{ns}".
/// Called after every mutation so certified HTTP reads never go stale.
pub fn refresh_indexes(reg: &Registry, store: &mut dyn BlobStore, namespace: Option<&str>) {
    let _ = store.put(
        "/",
        "application/json",
        None,
        list_namespaces_json(reg).into_bytes(),
    );
    let _ = store.put(
        "/api/extensions",
        "application/json",
        None,
        list_extensions_json(reg, store).into_bytes(),
    );
    let _ = store.put(
        "/api/codices",
        "application/json",
        None,
        list_codices_json(reg, store).into_bytes(),
    );
    if let Some(ns) = namespace {
        if reg.namespaces.contains_key(ns) {
            let _ = store.put(
                &format!("/{ns}"),
                "application/json",
                None,
                list_files_json(reg, ns).into_bytes(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Cache-Control max-age served for stored files (Python sent max-age=3600).
const FILE_MAX_AGE_SECS: u64 = 3600;

fn write_file(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    namespace: &str,
    path: &str,
    content_type: String,
    chunks: Vec<Vec<u8>>,
) -> Result<(u64, String), String> {
    let sha256 = sha256_hex(&chunks);
    let size: u64 = chunks.iter().map(|c| c.len() as u64).sum();

    if size == 0 {
        let filename = path.rsplit('/').next().unwrap_or(path);
        if filename.len() >= 5 && filename[filename.len() - 5..].eq_ignore_ascii_case(".wasm") {
            return Err("empty wasm not allowed".into());
        }
    }

    reg.ensure_namespace(namespace, &ctx.caller, ctx.now);
    store.put_chunked(
        &asset_key(namespace, path),
        &content_type,
        Some(FILE_MAX_AGE_SECS),
        chunks,
    )?;
    reg.set_file_meta(
        namespace,
        path,
        FileMeta {
            size,
            content_type,
            sha256: sha256.clone(),
            updated: ctx.now,
        },
    );
    refresh_indexes(reg, store, Some(namespace));
    Ok((size, sha256))
}

pub fn u_store_file(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/').to_string(),
        Err(e) => return err(e),
    };
    let content_b64 = match str_field(&params, "content_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let content_type = params
        .get("content_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| guess_content_type(&path));

    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    let content = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
        Ok(c) => c,
        Err(e) => return err(format!("Invalid base64: {e}")),
    };
    if let Some(e) = codex_manifest_gate(reg, ctx, &namespace, &path, &content) {
        return e;
    }

    match write_file(
        reg,
        store,
        ctx,
        &namespace,
        &path,
        content_type,
        vec![content],
    ) {
        Ok((size, sha256)) => json!({
            "ok": true,
            "namespace": namespace,
            "path": path,
            "size": size,
            "sha256": sha256,
        })
        .to_string(),
        Err(e) => err(e),
    }
}

pub fn u_delete_file(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/').to_string(),
        Err(e) => return err(e),
    };
    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    let existed = reg
        .files
        .get_mut(&namespace)
        .map(|files| files.remove(&path).is_some())
        .unwrap_or(false);
    if !existed {
        return err(format!("Not found: {namespace}/{path}"));
    }
    store.remove(&asset_key(&namespace, &path));
    refresh_indexes(reg, store, Some(&namespace));
    json!({"ok": true, "namespace": namespace, "path": path}).to_string()
}

pub fn u_update_namespace(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let description = params
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let Some(info) = reg.namespaces.get_mut(&namespace) else {
        return err(format!("Namespace '{namespace}' not found"));
    };
    info.description = description;
    refresh_indexes(reg, store, None);
    json!({"ok": true, "namespace": namespace}).to_string()
}

pub fn u_publish_namespace(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    let Some(info) = reg.namespaces.get_mut(&namespace) else {
        return err(format!("Namespace '{namespace}' not found"));
    };
    info.published = true;
    info.published_at = Some(ctx.now);
    refresh_indexes(reg, store, Some(&namespace));
    json!({"ok": true, "namespace": namespace}).to_string()
}

fn delete_namespace_impl(reg: &mut Registry, store: &mut dyn BlobStore, namespace: &str) -> u64 {
    let mut freed = 0u64;
    if let Some(files) = reg.files.remove(namespace) {
        for (path, meta) in files {
            freed += meta.size;
            store.remove(&asset_key(namespace, &path));
        }
    }
    store.remove(&format!("/{namespace}"));
    reg.namespaces.remove(namespace);
    reg.acl.remove(namespace);
    freed
}

pub fn u_delete_namespace(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    if !reg.namespaces.contains_key(&namespace) {
        return err(format!("Namespace '{namespace}' not found"));
    }
    delete_namespace_impl(reg, store, &namespace);
    refresh_indexes(reg, store, None);
    json!({"ok": true, "namespace": namespace}).to_string()
}

pub fn u_grant_publish(reg: &mut Registry, ctx: &CallerCtx, args: &str) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let principal = match str_field(&params, "principal") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let ns_acl = reg.acl.entry(namespace.clone()).or_default();
    if !ns_acl.contains(&principal) {
        ns_acl.push(principal.clone());
    }
    json!({"ok": true, "namespace": namespace, "principal": principal}).to_string()
}

pub fn u_revoke_publish(reg: &mut Registry, ctx: &CallerCtx, args: &str) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let principal = match str_field(&params, "principal") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    if let Some(ns_acl) = reg.acl.get_mut(&namespace) {
        ns_acl.retain(|p| p != &principal);
    }
    json!({"ok": true, "namespace": namespace, "principal": principal}).to_string()
}

// ---------------------------------------------------------------------------
// Chunked upload
// ---------------------------------------------------------------------------

pub fn u_store_file_chunk(reg: &mut Registry, ctx: &CallerCtx, args: &str) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/').to_string(),
        Err(e) => return err(e),
    };
    let Some(chunk_index) = params.get("chunk_index").and_then(|v| v.as_u64()) else {
        return err("missing or invalid field 'chunk_index'");
    };
    let Some(total_chunks) = params.get("total_chunks").and_then(|v| v.as_u64()) else {
        return err("missing or invalid field 'total_chunks'");
    };
    let data_b64 = match str_field(&params, "data_b64") {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let content_type = params
        .get("content_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| guess_content_type(&path));

    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(c) => c,
        Err(e) => return err(format!("Invalid base64: {e}")),
    };

    let entry = reg
        .pending
        .entry(pending_key(&namespace, &path))
        .or_insert_with(|| PendingUpload {
            total_chunks: total_chunks as u32,
            content_type,
            expected_sha256: String::new(),
            chunks: BTreeMap::new(),
        });
    entry
        .chunks
        .insert(chunk_index as u32, serde_bytes::ByteBuf::from(data));

    json!({
        "ok": true,
        "chunk_index": chunk_index,
        "uploaded": entry.chunks.len(),
        "total_chunks": total_chunks,
    })
    .to_string()
}

/// Shared finalize logic. Unlike the Python registry (which needed dozens of
/// incremental `finalize_chunked_file_step` calls to stay under the message
/// instruction budget), the whole assembly is cheap in Rust, so both finalize
/// entry points complete in a single message.
fn finalize_impl(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    namespace: &str,
    path: &str,
    expected_sha256: &str,
) -> Result<(u64, String, u32), String> {
    let key = pending_key(namespace, path);
    let Some(pending) = reg.pending.get(&key) else {
        return Err(format!("No pending upload for {namespace}/{path}"));
    };
    let total = pending.total_chunks;
    for i in 0..total {
        if !pending.chunks.contains_key(&i) {
            return Err(format!("Missing chunk {i} of {total}"));
        }
    }

    // Verify caller-provided hash before consuming the staged chunks, so a
    // mismatch leaves the upload intact for retry.
    let ordered: Vec<&[u8]> = (0..total)
        .map(|i| pending.chunks.get(&i).unwrap().as_ref())
        .collect();
    let actual_sha = sha256_hex(&ordered);
    let expected = if !expected_sha256.is_empty() {
        expected_sha256
    } else {
        pending.expected_sha256.as_str()
    };
    if !expected.is_empty() && expected != actual_sha {
        return Err(format!(
            "sha256 mismatch: expected {expected}, uploaded content hashes to {actual_sha}"
        ));
    }

    // Codex curation gate — a chunked manifest.json must not bypass the
    // kind: codex classification check in store_file.
    if path.rsplit('/').next() == Some("manifest.json") || namespace.starts_with(NS_PREFIX_CODEX) {
        let assembled: Vec<u8> = ordered.concat();
        if let Some(e) = codex_manifest_gate(reg, ctx, namespace, path, &assembled) {
            // gate returns a JSON error string; unwrap it back to a message
            let msg = serde_json::from_str::<Value>(&e)
                .ok()
                .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or(e);
            return Err(msg);
        }
    }

    let pending = reg.pending.remove(&key).unwrap();
    let content_type = if pending.content_type.is_empty() {
        guess_content_type(path)
    } else {
        pending.content_type.clone()
    };
    let chunks: Vec<Vec<u8>> = {
        let mut chunks_map = pending.chunks;
        (0..total)
            .map(|i| chunks_map.remove(&i).unwrap().into_vec())
            .collect()
    };
    write_file(reg, store, ctx, namespace, path, content_type, chunks)
        .map(|(size, sha)| (size, sha, total))
}

pub fn u_finalize_chunked_file(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/').to_string(),
        Err(e) => return err(e),
    };
    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    match finalize_impl(reg, store, ctx, &namespace, &path, "") {
        Ok((size, sha256, _total)) => json!({
            "ok": true,
            "namespace": namespace,
            "path": path,
            "size": size,
            "sha256": sha256,
        })
        .to_string(),
        Err(e) => err(e),
    }
}

pub fn u_finalize_chunked_file_step(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let path = match str_field(&params, "path") {
        Ok(v) => v.trim_start_matches('/').to_string(),
        Err(e) => return err(e),
    };
    let expected_sha256 = params
        .get("expected_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(e) = require_publisher(reg, ctx, &namespace) {
        return e;
    }
    // `batch_size` is accepted but ignored: assembly is cheap in Rust, so
    // the whole finalize completes in this one call (done=true immediately;
    // pollers observe instant completion).
    match finalize_impl(reg, store, ctx, &namespace, &path, &expected_sha256) {
        Ok((size, sha256, total)) => json!({
            "ok": true,
            "done": true,
            "processed": total,
            "total": total,
            "namespace": namespace,
            "path": path,
            "size": size,
            "sha256": sha256,
        })
        .to_string(),
        Err(e) => err(e),
    }
}

// ---------------------------------------------------------------------------
// Bulk restore (migration tooling)
// ---------------------------------------------------------------------------

/// Controller-only bulk restore used when migrating content between registry
/// canisters (e.g. the Python -> Rust cutover). Restores many files of one
/// namespace in a single message, preserving original metadata.
///
/// Args (JSON): {
///   "namespace": str,
///   "publish": bool (optional) — mark the namespace published,
///   "description": str (optional),
///   "files": [{"path", "content_b64", "content_type"?, "sha256"?, "updated"?}]
/// }
pub fn u_admin_restore_files(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let namespace = match str_field(&params, "namespace") {
        Ok(v) => v.to_string(),
        Err(e) => return err(e),
    };
    let files = params
        .get("files")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    reg.ensure_namespace(&namespace, &ctx.caller, ctx.now);

    let mut restored = 0usize;
    for file in &files {
        let path = match file.get("path").and_then(|v| v.as_str()) {
            Some(p) => p.trim_start_matches('/').to_string(),
            None => return err("file entry missing 'path'"),
        };
        let content_b64 = match file.get("content_b64").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return err(format!("file '{path}' missing 'content_b64'")),
        };
        let content = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
            Ok(c) => c,
            Err(e) => return err(format!("file '{path}': invalid base64: {e}")),
        };
        let actual_sha = sha256_hex(&[&content]);
        if let Some(expected) = file.get("sha256").and_then(|v| v.as_str()) {
            if !expected.is_empty() && expected != actual_sha {
                return err(format!(
                    "file '{path}': sha256 mismatch: expected {expected}, got {actual_sha}"
                ));
            }
        }
        let content_type = file
            .get("content_type")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| guess_content_type(&path));
        let updated = file
            .get("updated")
            .and_then(|v| v.as_u64())
            .unwrap_or(ctx.now);

        let size = content.len() as u64;
        if let Err(e) = store.put_chunked(
            &asset_key(&namespace, &path),
            &content_type,
            Some(FILE_MAX_AGE_SECS),
            vec![content],
        ) {
            return err(format!("file '{path}': {e}"));
        }
        reg.set_file_meta(
            &namespace,
            &path,
            FileMeta {
                size,
                content_type,
                sha256: actual_sha,
                updated,
            },
        );
        restored += 1;
    }

    if let Some(description) = params.get("description").and_then(|v| v.as_str()) {
        if let Some(info) = reg.namespaces.get_mut(&namespace) {
            info.description = description.to_string();
        }
    }
    if params.get("publish").and_then(|v| v.as_bool()) == Some(true) {
        if let Some(info) = reg.namespaces.get_mut(&namespace) {
            info.published = true;
            info.published_at = Some(ctx.now);
        }
    }

    refresh_indexes(reg, store, Some(&namespace));
    json!({"ok": true, "namespace": namespace, "restored": restored}).to_string()
}

// ---------------------------------------------------------------------------
// Purge
// ---------------------------------------------------------------------------

pub fn u_purge_old_versions(
    reg: &mut Registry,
    store: &mut dyn BlobStore,
    ctx: &CallerCtx,
    args: &str,
) -> String {
    if let Some(e) = require_controller(ctx) {
        return e;
    }
    let params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let keep = params
        .get("keep")
        .and_then(|v| v.as_u64())
        .unwrap_or(2)
        .max(1) as usize;
    let dry_run = params
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    const VERSIONED_PREFIXES: [&str; 3] = ["ext/", "codex/", "assistant/"];

    // Group versioned namespaces by "{prefix}{item_id}".
    let mut groups: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
    for (ns_name, ns_info) in &reg.namespaces {
        for pfx in VERSIONED_PREFIXES {
            if let Some(rest) = ns_name.strip_prefix(pfx) {
                if let Some((item_id, version)) = rest.split_once('/') {
                    groups.entry(format!("{pfx}{item_id}")).or_default().push((
                        ns_name.clone(),
                        version.to_string(),
                        ns_info.published,
                    ));
                }
                break;
            }
        }
    }

    let mut deleted_namespaces = Vec::new();
    let mut kept_namespaces: Vec<String> = Vec::new();
    let mut total_freed = 0u64;

    for (_group, entries) in groups {
        let mut published: Vec<_> = entries.iter().filter(|e| e.2).cloned().collect();
        let unpublished: Vec<_> = entries.iter().filter(|e| !e.2).cloned().collect();
        published.sort_by_key(|e| std::cmp::Reverse(parse_semver(&e.1)));

        for (ns, _, _) in published.iter().take(keep) {
            kept_namespaces.push(ns.clone());
        }
        let to_delete = published
            .iter()
            .skip(keep)
            .chain(unpublished.iter())
            .cloned()
            .collect::<Vec<_>>();

        for (ns, _, _) in to_delete {
            let ns_bytes: u64 = reg
                .ns_files(&ns)
                .map(|files| files.values().map(|f| f.size).sum())
                .unwrap_or(0);
            if !dry_run {
                delete_namespace_impl(reg, store, &ns);
            }
            deleted_namespaces.push(json!({"namespace": ns, "bytes": ns_bytes}));
            total_freed += ns_bytes;
        }
    }

    // Clean up old realm-base WASM builds in the "wasm" namespace.
    let mut deleted_wasm = Vec::new();
    let mut kept_wasm: Vec<String> = Vec::new();

    if reg.namespaces.contains_key(NS_PREFIX_WASM) {
        let wasm_files: Vec<(String, u64)> = reg
            .ns_files(NS_PREFIX_WASM)
            .map(|files| files.iter().map(|(p, m)| (p.clone(), m.size)).collect())
            .unwrap_or_default();

        let mut version_map: BTreeMap<&str, Vec<(String, String, u64)>> = BTreeMap::new();
        for (wf, size) in &wasm_files {
            if let Some(after_prefix) = wf.strip_prefix("realm-base-") {
                if let Some(ver) = after_prefix.strip_suffix(".wasm.gz") {
                    version_map
                        .entry("realm-base-*.wasm.gz")
                        .or_default()
                        .push((wf.clone(), ver.to_string(), *size));
                    continue;
                }
                if let Some(ver) = after_prefix.strip_suffix(".wasm") {
                    version_map.entry("realm-base-*.wasm").or_default().push((
                        wf.clone(),
                        ver.to_string(),
                        *size,
                    ));
                    continue;
                }
            }
            kept_wasm.push(wf.clone());
        }

        for (_key, mut entries) in version_map {
            entries.sort_by_key(|e| std::cmp::Reverse(parse_semver(&e.1)));
            for (wf, _, _) in entries.iter().take(keep) {
                kept_wasm.push(wf.clone());
            }
            for (wf, _, size) in entries.iter().skip(keep) {
                if !dry_run {
                    store.remove(&asset_key(NS_PREFIX_WASM, wf));
                    if let Some(files) = reg.files.get_mut(NS_PREFIX_WASM) {
                        files.remove(wf);
                    }
                }
                deleted_wasm.push(json!({"path": wf, "bytes": size}));
                total_freed += size;
            }
        }
    }

    // Orphaned staged chunks (pending uploads never finalized).
    let mut orphan_freed = 0u64;
    if !dry_run {
        for pending in reg.pending.values() {
            orphan_freed += pending.chunks.values().map(|c| c.len() as u64).sum::<u64>();
        }
        reg.pending.clear();
        refresh_indexes(reg, store, None);
    }

    kept_namespaces.sort();
    kept_wasm.sort();
    json!({
        "ok": true,
        "dry_run": dry_run,
        "deleted_namespaces": deleted_namespaces,
        "deleted_wasm_files": deleted_wasm,
        "kept_namespaces": kept_namespaces,
        "kept_wasm_files": kept_wasm,
        "total_freed_bytes": total_freed,
        "orphaned_chunks_freed_bytes": orphan_freed,
    })
    .to_string()
}
