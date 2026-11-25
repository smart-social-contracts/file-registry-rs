//! File Registry canister — Rust drop-in replacement for the Python
//! `file_registry` (realms/src/file_registry/main.py), built on top of the
//! `ic-certified-assets` state machine.
//!
//! - Same Candid interface and JSON contracts as the Python canister.
//! - File bytes live in the certified asset store, so HTTP GETs are served
//!   as certified *query* responses (free-tier reads, no update-call burn).
//! - Wrapper-owned index: namespaces, per-file metadata, publisher ACL,
//!   pending chunked uploads.

pub mod api;
pub mod registry;
pub mod store;

pub use registry::Registry;

use api::CallerCtx;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_certified_assets::asset_certification::types::http::{
    HttpRequest, HttpResponse, StreamingCallbackHttpResponse, StreamingCallbackToken,
};
use ic_certified_assets::StableStateV2;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use store::CertifiedStore;

// Read by the HTTP gateway via the wasm custom section; never referenced
// from code.
#[cfg(target_arch = "wasm32")]
#[unsafe(link_section = "icp:public supported_certificate_versions")]
#[used]
static CERTIFICATE_VERSIONS: [u8; 3] = ic_certified_assets::SUPPORTED_CERTIFICATE_VERSIONS;

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry::default());
}

fn ctx() -> CallerCtx {
    let caller = ic_cdk::api::msg_caller();
    CallerCtx {
        caller: caller.to_text(),
        is_controller: ic_cdk::api::is_controller(&caller),
        now: ic_cdk::api::time(),
    }
}

fn with_reg<R>(f: impl FnOnce(&Registry) -> R) -> R {
    REGISTRY.with(|r| f(&r.borrow()))
}

fn with_reg_mut<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    REGISTRY.with(|r| f(&mut r.borrow_mut()))
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

#[query]
fn list_namespaces() -> String {
    with_reg(api::list_namespaces_json)
}

#[query]
fn list_files(args: String) -> String {
    with_reg(|reg| api::q_list_files(reg, &args))
}

#[query]
fn get_file(args: String) -> String {
    with_reg(|reg| api::q_get_file(reg, &CertifiedStore, &args))
}

#[query]
fn get_file_size(args: String) -> String {
    with_reg(|reg| api::q_get_file_size(reg, &CertifiedStore, &args))
}

#[query]
fn get_file_chunk(args: String) -> String {
    api::q_get_file_chunk(&CertifiedStore, &args)
}

#[query]
fn get_file_chunk_icc(namespace: String, path: String, offset: String, length: String) -> String {
    let Ok(offset) = parse_int_arg(&offset, 0) else {
        return r#"{"error":"offset and length must be integers"}"#.to_string();
    };
    let Ok(length) = parse_int_arg(&length, api::MAX_CHUNK_READ_BYTES as i64) else {
        return r#"{"error":"offset and length must be integers"}"#.to_string();
    };
    api::get_file_chunk_impl(&CertifiedStore, &namespace, &path, offset, length)
}

fn parse_int_arg(s: &str, default: i64) -> Result<i64, ()> {
    if s.is_empty() {
        return Ok(default);
    }
    s.parse::<i64>().map_err(|_| ())
}

#[query]
fn get_file_size_icc(namespace: String, path: String) -> String {
    with_reg(|reg| {
        api::q_get_file_size(
            reg,
            &CertifiedStore,
            &serde_json::json!({"namespace": namespace, "path": path}).to_string(),
        )
    })
}

#[query]
fn list_files_icc(namespace: String) -> String {
    with_reg(|reg| api::list_files_json(reg, &namespace))
}

#[query]
fn get_stats() -> String {
    with_reg(api::q_get_stats)
}

#[query]
fn get_acl() -> String {
    with_reg(api::q_get_acl)
}

#[query]
fn list_extensions() -> String {
    with_reg(|reg| api::list_extensions_json(reg, &CertifiedStore))
}

#[query]
fn list_codices() -> String {
    with_reg(|reg| api::list_codices_json(reg, &CertifiedStore))
}

#[query]
fn latest_version(args: String) -> String {
    with_reg(|reg| api::q_latest_version(reg, &args))
}

#[query]
fn get_extension_manifest(args: String) -> String {
    with_reg(|reg| api::q_get_extension_manifest(reg, &CertifiedStore, &args))
}

#[query]
fn get_backend_files(args: String) -> String {
    let params: serde_json::Value = match serde_json::from_str(&args) {
        Ok(p) => p,
        Err(e) => return format!(r#"{{"error":"invalid args (not JSON): {e}"}}"#),
    };
    let category = params
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let item_id = params.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
    let version = params.get("version").and_then(|v| v.as_str()).unwrap_or("");
    with_reg(|reg| api::get_backend_files_impl(reg, &CertifiedStore, category, item_id, version))
}

#[query]
fn get_backend_files_icc(category: String, item_id: String, version: String) -> String {
    with_reg(|reg| api::get_backend_files_impl(reg, &CertifiedStore, &category, &item_id, &version))
}

#[query]
fn get_frontend_files(args: String) -> String {
    let params: serde_json::Value = match serde_json::from_str(&args) {
        Ok(p) => p,
        Err(e) => return format!(r#"{{"error":"invalid args (not JSON): {e}"}}"#),
    };
    let item_id = params.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
    let version = params.get("version").and_then(|v| v.as_str()).unwrap_or("");
    with_reg(|reg| api::get_frontend_files_impl(reg, &CertifiedStore, item_id, version))
}

#[query]
fn get_frontend_files_icc(item_id: String, version: String) -> String {
    with_reg(|reg| api::get_frontend_files_impl(reg, &CertifiedStore, &item_id, &version))
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

#[update]
fn store_file(args: String) -> String {
    with_reg_mut(|reg| api::u_store_file(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn delete_file(args: String) -> String {
    with_reg_mut(|reg| api::u_delete_file(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn update_namespace(args: String) -> String {
    with_reg_mut(|reg| api::u_update_namespace(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn publish_namespace(args: String) -> String {
    with_reg_mut(|reg| api::u_publish_namespace(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn delete_namespace(args: String) -> String {
    with_reg_mut(|reg| api::u_delete_namespace(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn purge_old_versions(args: String) -> String {
    with_reg_mut(|reg| api::u_purge_old_versions(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn grant_publish(args: String) -> String {
    with_reg_mut(|reg| api::u_grant_publish(reg, &ctx(), &args))
}

#[update]
fn set_namespace_policy(args: String) -> String {
    with_reg_mut(|reg| api::u_set_namespace_policy(reg, &ctx(), &args))
}

#[update]
fn revoke_publish(args: String) -> String {
    with_reg_mut(|reg| api::u_revoke_publish(reg, &ctx(), &args))
}

#[update]
fn admin_restore_files(args: String) -> String {
    with_reg_mut(|reg| api::u_admin_restore_files(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn store_file_chunk(args: String) -> String {
    with_reg_mut(|reg| api::u_store_file_chunk(reg, &ctx(), &args))
}

#[update]
fn finalize_chunked_file(args: String) -> String {
    with_reg_mut(|reg| api::u_finalize_chunked_file(reg, &mut CertifiedStore, &ctx(), &args))
}

#[update]
fn finalize_chunked_file_step(args: String) -> String {
    with_reg_mut(|reg| api::u_finalize_chunked_file_step(reg, &mut CertifiedStore, &ctx(), &args))
}

// ---------------------------------------------------------------------------
// HTTP — certified query responses served straight from the asset store
// ---------------------------------------------------------------------------

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    ic_certified_assets::http_request(req)
}

#[query]
fn http_request_streaming_callback(token: StreamingCallbackToken) -> StreamingCallbackHttpResponse {
    ic_certified_assets::http_request_streaming_callback(token)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct StableState {
    assets: StableStateV2,
    registry: Registry,
}

#[init]
fn canister_init() {
    ic_certified_assets::init(None);
    with_reg_mut(|reg| api::refresh_indexes(reg, &mut CertifiedStore, None));
}

#[pre_upgrade]
fn canister_pre_upgrade() {
    let stable = StableState {
        assets: ic_certified_assets::pre_upgrade(),
        registry: REGISTRY.take(),
    };
    let mut writer = ic_cdk::stable::StableWriter::default();
    serde_cbor::to_writer(&mut writer, &stable).expect("failed to serialize stable state");
}

#[post_upgrade]
fn canister_post_upgrade() {
    let reader = ic_cdk::stable::StableReader::default();
    let stable: StableState =
        from_reader_ignore_trailing_data(reader).expect("failed to deserialize stable state");
    ic_certified_assets::post_upgrade(stable.assets, None);
    REGISTRY.with(|r| r.replace(stable.registry));
    // The index assets were rendered by the previous build, so an upgrade that
    // changes their shape leaves HTTP serving stale until the next write.
    with_reg_mut(|reg| api::refresh_indexes(reg, &mut CertifiedStore, None));
}

fn from_reader_ignore_trailing_data<T, R>(reader: R) -> Result<T, serde_cbor::Error>
where
    T: serde::de::DeserializeOwned,
    R: std::io::Read,
{
    let mut deserializer = serde_cbor::de::Deserializer::from_reader(reader);
    // Do not call deserializer.end(): stable memory has trailing zero pages.
    serde::de::Deserialize::deserialize(&mut deserializer)
}

#[query]
fn __get_candid_interface_tmp_hack() -> String {
    include_str!("../file_registry.did").to_string()
}
