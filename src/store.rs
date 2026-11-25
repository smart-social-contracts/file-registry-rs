//! Abstraction over the byte store. Production uses the certified asset
//! store (`ic-certified-assets`); tests use an in-memory map. Keys are
//! HTTP-style absolute paths, e.g. "/ext/voting/1.0.3/manifest.json".

pub trait BlobStore {
    /// Create or replace an asset from ordered chunks. `max_age` becomes the
    /// Cache-Control max-age served over HTTP.
    fn put_chunked(
        &mut self,
        key: &str,
        content_type: &str,
        max_age: Option<u64>,
        chunks: Vec<Vec<u8>>,
    ) -> Result<(), String>;

    fn read(&self, key: &str) -> Option<Vec<u8>>;

    /// Read `length` bytes starting at `offset`. Returns (bytes, total_size).
    /// `offset` may equal total_size (empty slice, eof). None if the key does
    /// not exist or offset is out of range.
    fn read_range(&self, key: &str, offset: u64, length: u64) -> Option<(Vec<u8>, u64)>;

    fn remove(&mut self, key: &str);

    fn put(
        &mut self,
        key: &str,
        content_type: &str,
        max_age: Option<u64>,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        self.put_chunked(key, content_type, max_age, vec![bytes])
    }
}

pub fn asset_key(namespace: &str, path: &str) -> String {
    if path.is_empty() {
        format!("/{namespace}")
    } else {
        format!("/{namespace}/{path}")
    }
}

// ---------------------------------------------------------------------------
// In-memory implementation for unit tests
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct MemStore {
    pub blobs: std::collections::BTreeMap<String, Vec<u8>>,
}

impl BlobStore for MemStore {
    fn put_chunked(
        &mut self,
        key: &str,
        _content_type: &str,
        _max_age: Option<u64>,
        chunks: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        self.blobs.insert(key.to_string(), chunks.concat());
        Ok(())
    }

    fn read(&self, key: &str) -> Option<Vec<u8>> {
        self.blobs.get(key).cloned()
    }

    fn read_range(&self, key: &str, offset: u64, length: u64) -> Option<(Vec<u8>, u64)> {
        let blob = self.blobs.get(key)?;
        let total = blob.len() as u64;
        if offset > total {
            return None;
        }
        let end = (offset + length).min(total);
        Some((blob[offset as usize..end as usize].to_vec(), total))
    }

    fn remove(&mut self, key: &str) {
        self.blobs.remove(key);
    }
}

// ---------------------------------------------------------------------------
// Certified asset store implementation
// ---------------------------------------------------------------------------

use ic_certified_assets::system_context::SystemContext;
use ic_certified_assets::types::{
    CreateAssetArguments, CreateChunksArg, DeleteAssetArguments, DeleteBatchArguments, GetArg,
    GetChunkArg, SetAssetContentArguments,
};

const CORS_HEADERS: &[(&str, &str)] = &[
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
];

fn cors_headers() -> std::collections::BTreeMap<String, String> {
    CORS_HEADERS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// BlobStore backed by the embedded `ic-certified-assets` state machine.
/// Every asset is stored with a single "identity" encoding and CORS headers,
/// and served over HTTP as a certified query response.
pub struct CertifiedStore;

impl BlobStore for CertifiedStore {
    fn put_chunked(
        &mut self,
        key: &str,
        content_type: &str,
        max_age: Option<u64>,
        chunks: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let ctx = SystemContext::new();
        ic_certified_assets::with_state_mut(|s| {
            s.delete_asset(DeleteAssetArguments {
                key: key.to_string(),
            });

            s.create_asset(CreateAssetArguments {
                key: key.to_string(),
                content_type: content_type.to_string(),
                max_age,
                headers: Some(cors_headers()),
                enable_aliasing: Some(false),
                allow_raw_access: Some(true),
            })?;

            let result = if chunks.len() == 1 {
                // Single chunk: no batch needed.
                let content = chunks.into_iter().next().unwrap();
                s.set_asset_content(
                    SetAssetContentArguments {
                        key: key.to_string(),
                        content_encoding: "identity".to_string(),
                        chunk_ids: vec![],
                        last_chunk: Some(serde_bytes::ByteBuf::from(content)),
                        sha256: None,
                    },
                    &ctx,
                )
            } else {
                // Multi-chunk: stage through a transient batch within this
                // single message, then drop the batch.
                let batch_id = s.create_batch(&ctx)?;
                let chunk_ids = s.create_chunks(
                    CreateChunksArg {
                        batch_id: batch_id.clone(),
                        content: chunks.into_iter().map(serde_bytes::ByteBuf::from).collect(),
                    },
                    &ctx,
                )?;
                let r = s.set_asset_content(
                    SetAssetContentArguments {
                        key: key.to_string(),
                        content_encoding: "identity".to_string(),
                        chunk_ids,
                        last_chunk: None,
                        sha256: None,
                    },
                    &ctx,
                );
                let _ = s.delete_batch(DeleteBatchArguments { batch_id });
                r
            };

            ic_cdk::api::certified_data_set(s.root_hash());
            result
        })
    }

    fn read(&self, key: &str) -> Option<Vec<u8>> {
        ic_certified_assets::with_state(|s| {
            let enc = s
                .get(GetArg {
                    key: key.to_string(),
                    accept_encodings: vec!["identity".to_string()],
                })
                .ok()?;
            let total = nat_to_u64(&enc.total_length) as usize;
            let mut out: Vec<u8> = Vec::with_capacity(total);
            out.extend_from_slice(&enc.content);
            let mut index = 1u64;
            while out.len() < total {
                let chunk = s
                    .get_chunk(GetChunkArg {
                        key: key.to_string(),
                        content_encoding: "identity".to_string(),
                        index: candid::Nat::from(index),
                        sha256: enc.sha256.clone(),
                    })
                    .ok()?;
                out.extend_from_slice(&chunk);
                index += 1;
            }
            Some(out)
        })
    }

    fn read_range(&self, key: &str, offset: u64, length: u64) -> Option<(Vec<u8>, u64)> {
        ic_certified_assets::with_state(|s| {
            let enc = s
                .get(GetArg {
                    key: key.to_string(),
                    accept_encodings: vec!["identity".to_string()],
                })
                .ok()?;
            let total = nat_to_u64(&enc.total_length);
            if offset > total {
                return None;
            }
            let want_end = (offset + length).min(total);
            let mut out: Vec<u8> = Vec::with_capacity((want_end - offset) as usize);

            // Walk stored chunks; chunk 0 comes with the get() response.
            let mut pos: u64 = 0;
            let mut index = 0u64;
            while pos < want_end && pos < total {
                let chunk: Vec<u8> = if index == 0 {
                    enc.content.to_vec()
                } else {
                    s.get_chunk(GetChunkArg {
                        key: key.to_string(),
                        content_encoding: "identity".to_string(),
                        index: candid::Nat::from(index),
                        sha256: enc.sha256.clone(),
                    })
                    .ok()?
                    .to_vec()
                };
                let chunk_len = chunk.len() as u64;
                let chunk_end = pos + chunk_len;
                if chunk_end > offset {
                    let from = offset.saturating_sub(pos) as usize;
                    let to = (want_end.min(chunk_end) - pos) as usize;
                    out.extend_from_slice(&chunk[from..to]);
                }
                pos = chunk_end;
                index += 1;
                if chunk_len == 0 {
                    break;
                }
            }
            Some((out, total))
        })
    }

    fn remove(&mut self, key: &str) {
        ic_certified_assets::with_state_mut(|s| {
            s.delete_asset(DeleteAssetArguments {
                key: key.to_string(),
            });
            ic_cdk::api::certified_data_set(s.root_hash());
        });
    }
}

fn nat_to_u64(n: &candid::Nat) -> u64 {
    use num_traits_shim::ToU64;
    n.to_u64()
}

/// candid::Nat exposes 0.4 num-bigint internally; avoid pulling num-traits
/// directly by going through the string representation only on overflow.
mod num_traits_shim {
    pub trait ToU64 {
        fn to_u64(&self) -> u64;
    }
    impl ToU64 for candid::Nat {
        fn to_u64(&self) -> u64 {
            // Nat displays with '_' separators, e.g. "1_000_000".
            let s = self.0.to_string().replace('_', "");
            s.parse::<u64>().unwrap_or(u64::MAX)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_store_range_reads() {
        let mut s = MemStore::default();
        s.put("/a/b", "text/plain", None, b"hello world".to_vec())
            .unwrap();
        assert_eq!(s.read("/a/b").unwrap(), b"hello world");
        let (slice, total) = s.read_range("/a/b", 6, 5).unwrap();
        assert_eq!(slice, b"world");
        assert_eq!(total, 11);
        let (slice, total) = s.read_range("/a/b", 11, 5).unwrap();
        assert!(slice.is_empty());
        assert_eq!(total, 11);
        assert!(s.read_range("/a/b", 12, 1).is_none());
        assert!(s.read_range("/nope", 0, 1).is_none());
    }
}
