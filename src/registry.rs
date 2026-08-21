//! Registry index: namespaces, per-file metadata, publisher ACL, pending
//! chunked uploads. This is the wrapper-owned state layered on top of the
//! certified asset store (which owns the actual bytes).
//!
//! JSON shapes and semantics are a 1:1 port of the Python `file_registry`
//! canister (realms/src/file_registry/main.py) so existing clients work
//! unchanged.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const NS_PREFIX_EXT: &str = "ext/";
pub const NS_PREFIX_CODEX: &str = "codex/";
pub const NS_PREFIX_WASM: &str = "wasm";
/// ACL key holding principals allowed to publish `kind: codex` packages.
pub const CODEX_CURATORS_ACL_KEY: &str = "_codex_curators";

/// Suffix -> content type, checked in order (first match wins), same table
/// as the Python implementation.
pub const CONTENT_TYPES: &[(&str, &str)] = &[
    (".py", "text/plain"),
    (".js", "application/javascript"),
    (".mjs", "application/javascript"),
    (".json", "application/json"),
    (".html", "text/html"),
    (".css", "text/css"),
    (".wasm", "application/wasm"),
    (".txt", "text/plain"),
    (".md", "text/markdown"),
    (".svg", "image/svg+xml"),
    (".png", "image/png"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".gif", "image/gif"),
    (".ico", "image/x-icon"),
    (".ts", "text/plain"),
    (".toml", "text/plain"),
    (".yaml", "text/plain"),
    (".yml", "text/plain"),
    (".svelte", "text/plain"),
];

pub fn guess_content_type(path: &str) -> String {
    for (suffix, ct) in CONTENT_TYPES {
        if path.ends_with(suffix) {
            return (*ct).to_string();
        }
    }
    "application/octet-stream".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FileMeta {
    pub size: u64,
    pub content_type: String,
    pub sha256: String,
    pub updated: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NamespaceInfo {
    pub created: u64,
    pub owner: String,
    pub description: String,
    pub published: bool,
    pub published_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PendingUpload {
    pub total_chunks: u32,
    pub content_type: String,
    pub expected_sha256: String,
    /// chunk_index -> bytes; chunks may arrive out of order.
    pub chunks: BTreeMap<u32, serde_bytes::ByteBuf>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Registry {
    pub namespaces: BTreeMap<String, NamespaceInfo>,
    /// namespace -> path -> metadata
    pub files: BTreeMap<String, BTreeMap<String, FileMeta>>,
    /// namespace (or special key) -> allowed publisher principals
    pub acl: BTreeMap<String, Vec<String>>,
    /// "{namespace}\n{path}" -> staged chunked upload
    pub pending: BTreeMap<String, PendingUpload>,
}

pub fn pending_key(namespace: &str, path: &str) -> String {
    format!("{namespace}\n{path}")
}

impl Registry {
    pub fn ensure_namespace(&mut self, namespace: &str, owner: &str, now: u64) {
        if !self.namespaces.contains_key(namespace) {
            self.namespaces.insert(
                namespace.to_string(),
                NamespaceInfo {
                    created: now,
                    owner: owner.to_string(),
                    description: String::new(),
                    published: false,
                    published_at: None,
                },
            );
        }
    }

    pub fn ns_files(&self, namespace: &str) -> Option<&BTreeMap<String, FileMeta>> {
        self.files.get(namespace)
    }

    /// Record file metadata.
    pub fn set_file_meta(&mut self, namespace: &str, path: &str, meta: FileMeta) {
        self.files
            .entry(namespace.to_string())
            .or_default()
            .insert(path.to_string(), meta);
    }
}

// ---------------------------------------------------------------------------
// Version helpers (port of the Python semver logic, including its quirks)
// ---------------------------------------------------------------------------

/// Parse "1.2.3" -> [1, 2, 3]. Any non-numeric part makes the whole string
/// parse as [0, 0, 0] (Python behavior).
pub fn parse_semver(version: &str) -> Vec<i64> {
    let mut out = Vec::new();
    for part in version.split('.') {
        match part.parse::<i64>() {
            Ok(n) => out.push(n),
            Err(_) => return vec![0, 0, 0],
        }
    }
    if out.is_empty() {
        vec![0, 0, 0]
    } else {
        out
    }
}

/// Highest published version under `prefix` (e.g. "ext/voting/").
pub fn find_latest_version(namespaces: &BTreeMap<String, NamespaceInfo>, prefix: &str) -> String {
    let mut best_version = String::new();
    let mut best_tuple: Vec<i64> = vec![-1];
    for (ns_name, ns_info) in namespaces {
        if ns_name.starts_with(prefix) && ns_info.published {
            let version = &ns_name[prefix.len()..];
            if version.contains('/') {
                continue;
            }
            let vt = parse_semver(version);
            if vt > best_tuple {
                best_tuple = vt;
                best_version = version.to_string();
            }
        }
    }
    best_version
}

pub fn published_versions(
    namespaces: &BTreeMap<String, NamespaceInfo>,
    prefix: &str,
) -> Vec<String> {
    let mut versions = Vec::new();
    for (ns_name, ns_info) in namespaces {
        if ns_name.starts_with(prefix) && ns_info.published {
            let version = &ns_name[prefix.len()..];
            if !version.contains('/') {
                versions.push(version.to_string());
            }
        }
    }
    versions
}

/// Does `version` satisfy a pin spec? Supports exact ("1.2.3"), wildcard
/// ("1.2.x", "1.x", "1.2.*"), caret ("^1.2.3") and tilde ("~1.2.3").
pub fn spec_matches(spec: &str, version: &str) -> bool {
    let spec = spec.trim();
    let vt = parse_semver(version);

    if spec.starts_with('^') || spec.starts_with('~') {
        let base = parse_semver(&spec[1..]);
        if vt < base {
            return false;
        }
        if vt.first() != base.first() {
            return false;
        }
        if spec.starts_with('~') && (vt.len() < 2 || base.len() < 2 || vt[1] != base[1]) {
            return false;
        }
        return true;
    }

    let lower = spec.to_lowercase();
    if lower.contains('x') || spec.contains('*') {
        let spec_norm = lower.replace('*', "x");
        let spec_parts: Vec<&str> = spec_norm.split('.').collect();
        let version_parts: Vec<&str> = version.split('.').collect();
        for (i, sp) in spec_parts.iter().enumerate() {
            if *sp == "x" {
                return true;
            }
            if i >= version_parts.len() || *sp != version_parts[i] {
                return false;
            }
        }
        return spec_parts.len() == version_parts.len();
    }

    spec == version
}

pub fn is_range_spec(spec: &str) -> bool {
    let s = spec.trim().to_lowercase();
    s.starts_with('^') || s.starts_with('~') || s.split('.').any(|p| p == "x") || s.contains('*')
}

/// Resolve a version spec to a concrete published version. Empty / "latest"
/// resolves to the highest published version; range specs resolve to the
/// highest published match; exact versions pass through. Returns "" when
/// nothing matches.
pub fn resolve_version_spec(
    namespaces: &BTreeMap<String, NamespaceInfo>,
    prefix: &str,
    spec: &str,
) -> String {
    let spec = spec.trim();
    if spec.is_empty() || spec.eq_ignore_ascii_case("latest") {
        return find_latest_version(namespaces, prefix);
    }
    if !is_range_spec(spec) {
        return spec.to_string();
    }
    let mut best = String::new();
    let mut best_tuple: Vec<i64> = vec![-1];
    for version in published_versions(namespaces, prefix) {
        if spec_matches(spec, &version) {
            let vt = parse_semver(&version);
            if vt > best_tuple {
                best_tuple = vt;
                best = version;
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(published: bool) -> NamespaceInfo {
        NamespaceInfo {
            created: 1,
            owner: "o".into(),
            description: String::new(),
            published,
            published_at: None,
        }
    }

    #[test]
    fn semver_parsing() {
        assert_eq!(parse_semver("1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_semver("1.10"), vec![1, 10]);
        assert_eq!(parse_semver("abc"), vec![0, 0, 0]);
        assert_eq!(parse_semver("1.2.beta"), vec![0, 0, 0]);
        assert!(parse_semver("1.10.0") > parse_semver("1.9.9"));
        // Python tuple semantics: shorter prefix compares less.
        assert!(parse_semver("1.2") < parse_semver("1.2.0"));
    }

    #[test]
    fn latest_version_skips_unpublished_and_subpaths() {
        let mut m = BTreeMap::new();
        m.insert("ext/voting/1.0.0".to_string(), ns(true));
        m.insert("ext/voting/1.0.3".to_string(), ns(true));
        m.insert("ext/voting/2.0.0".to_string(), ns(false));
        m.insert("ext/voting/1.0.4/extra".to_string(), ns(true));
        assert_eq!(find_latest_version(&m, "ext/voting/"), "1.0.3");
        assert_eq!(find_latest_version(&m, "ext/nope/"), "");
    }

    #[test]
    fn spec_matching() {
        assert!(spec_matches("1.2.3", "1.2.3"));
        assert!(!spec_matches("1.2.3", "1.2.4"));
        assert!(spec_matches("1.2.x", "1.2.9"));
        assert!(!spec_matches("1.2.x", "1.3.0"));
        assert!(spec_matches("1.x", "1.9.9"));
        assert!(spec_matches("1.2.*", "1.2.0"));
        assert!(spec_matches("^1.2.3", "1.9.0"));
        assert!(!spec_matches("^1.2.3", "2.0.0"));
        assert!(!spec_matches("^1.2.3", "1.2.2"));
        assert!(spec_matches("~1.2.3", "1.2.9"));
        assert!(!spec_matches("~1.2.3", "1.3.0"));
    }

    #[test]
    fn range_spec_detection() {
        assert!(is_range_spec("^1.0.0"));
        assert!(is_range_spec("~1.2.3"));
        assert!(is_range_spec("1.2.x"));
        assert!(is_range_spec("1.2.*"));
        assert!(!is_range_spec("1.2.3"));
        // "x" must be a full component, not a substring of one
        assert!(!is_range_spec("1.0.0-xyz"));
    }

    #[test]
    fn resolve_spec() {
        let mut m = BTreeMap::new();
        m.insert("ext/gov/1.0.0".to_string(), ns(true));
        m.insert("ext/gov/1.1.0".to_string(), ns(true));
        m.insert("ext/gov/1.2.0".to_string(), ns(false));
        m.insert("ext/gov/2.0.0".to_string(), ns(true));
        assert_eq!(resolve_version_spec(&m, "ext/gov/", ""), "2.0.0");
        assert_eq!(resolve_version_spec(&m, "ext/gov/", "latest"), "2.0.0");
        assert_eq!(resolve_version_spec(&m, "ext/gov/", "1.x"), "1.1.0");
        assert_eq!(resolve_version_spec(&m, "ext/gov/", "^1.0.0"), "1.1.0");
        // exact spec passes through even if unpublished (caller checks existence)
        assert_eq!(resolve_version_spec(&m, "ext/gov/", "1.2.0"), "1.2.0");
        assert_eq!(resolve_version_spec(&m, "ext/gov/", "3.x"), "");
    }

    #[test]
    fn content_type_guessing() {
        assert_eq!(guess_content_type("a/b/entry.py"), "text/plain");
        assert_eq!(guess_content_type("manifest.json"), "application/json");
        assert_eq!(
            guess_content_type("realm-base-1.0.0.wasm"),
            "application/wasm"
        );
        assert_eq!(
            guess_content_type("realm-base-1.0.0.wasm.gz"),
            "application/octet-stream"
        );
    }
}
