//! Files (spec section 5): padding, chunk encryption and the Merkle tree
//! that lets any party verify and resume a transfer without a key.

use crate::kdf::kdf;
use crate::{Error, Result, aead};

/// `C`: plaintext bytes per chunk.
pub const CHUNK: usize = 1 << 20;
/// The largest encrypted chunk.
pub const MAX_CIPHER_CHUNK: usize = CHUNK + aead::TAG_LEN;
/// No file is padded to less than this.
pub const MIN_PADDED: u64 = 4096;
pub const HASH_LEN: usize = 32;

const CHUNK_CONTEXT: &[u8] = b"sayso/v1/chunk";

/// Padmé: round `len` up so that at most about 12% is added and the result
/// reveals only `O(log log len)` bits of the true length.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros() as u64; // floor(log2(len))
    let s = 64 - e.leading_zeros() as u64; // floor(log2(e)) + 1
    let mask = (1u64 << (e - s)) - 1;
    match len.checked_add(mask) {
        Some(sum) => sum & !mask,
        None => len,
    }
}

/// How a file of a given size is laid out as chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilePlan {
    /// True size in bytes.
    pub size: u64,
    /// Size after zero padding.
    pub padded: u64,
    /// Number of chunks, at least one.
    pub chunks: u64,
}

impl FilePlan {
    /// The plan a sender uses for a file of `size` bytes.
    pub fn for_size(size: u64) -> Self {
        let padded = padme(size).max(MIN_PADDED);
        Self {
            size,
            padded,
            chunks: padded.div_ceil(CHUNK as u64),
        }
    }

    /// Rebuild a plan from the two sizes in a `File` entry, rejecting any
    /// pair a conforming sender would not produce.
    pub fn from_parts(size: u64, padded: u64) -> Result<Self> {
        let plan = Self::for_size(size);
        if plan.padded != padded {
            return Err(Error::Invalid("file padding"));
        }
        Ok(plan)
    }

    fn check(&self, i: u64) -> Result<()> {
        if i >= self.chunks {
            return Err(Error::Invalid("chunk index"));
        }
        Ok(())
    }

    /// Plaintext bytes in chunk `i`, padding included.
    pub fn plain_len(&self, i: u64) -> Result<usize> {
        self.check(i)?;
        let start = i * CHUNK as u64;
        Ok((self.padded - start).min(CHUNK as u64) as usize)
    }

    /// Bytes of the real file in chunk `i`.
    pub fn data_len(&self, i: u64) -> Result<usize> {
        self.check(i)?;
        let start = i * CHUNK as u64;
        Ok(self.size.saturating_sub(start).min(CHUNK as u64) as usize)
    }

    /// Total bytes of all encrypted chunks.
    pub fn total_cipher(&self) -> u64 {
        self.padded + self.chunks * aead::TAG_LEN as u64
    }
}

fn chunk_nonce(i: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&i.to_be_bytes());
    nonce
}

fn chunk_aad(chunks: u64) -> Vec<u8> {
    [CHUNK_CONTEXT, &chunks.to_be_bytes()].concat()
}

/// Encrypt chunk `i`. `data` is exactly the file's bytes for that chunk
/// (`plan.data_len(i)` of them); padding is added here.
///
/// `key` must be 32 fresh random bytes per file, never reused.
pub fn encrypt_chunk(key: &[u8; 32], plan: &FilePlan, i: u64, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() != plan.data_len(i)? {
        return Err(Error::Invalid("chunk length"));
    }
    let mut plain = data.to_vec();
    plain.resize(plan.plain_len(i)?, 0);
    Ok(aead::seal(
        key,
        &chunk_nonce(i),
        &chunk_aad(plan.chunks),
        &plain,
    ))
}

/// Decrypt chunk `i` and strip its padding.
pub fn decrypt_chunk(key: &[u8; 32], plan: &FilePlan, i: u64, cipher: &[u8]) -> Result<Vec<u8>> {
    let data_len = plan.data_len(i)?;
    let mut plain = aead::open(key, &chunk_nonce(i), &chunk_aad(plan.chunks), cipher)?;
    if plain.len() != plan.plain_len(i)? {
        return Err(Error::Invalid("chunk length"));
    }
    plain.truncate(data_len);
    Ok(plain)
}

/// The Merkle leaf of one encrypted chunk.
pub fn leaf(cipher: &[u8]) -> [u8; HASH_LEN] {
    kdf("sayso/v1/merkle/leaf", &[cipher])
}

fn subtree(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    match leaves.len() {
        1 => leaves[0],
        n => {
            // RFC 6962 shape: split at the largest power of two below n.
            let split = n.next_power_of_two() / 2;
            let (left, right) = leaves.split_at(split);
            kdf("sayso/v1/merkle/node", &[&subtree(left), &subtree(right)])
        }
    }
}

/// The root that names a file: binds the leaf count and total length, so two
/// different chunkings can never share a root.
pub fn merkle_root(leaves: &[[u8; HASH_LEN]], total_cipher: u64) -> Result<[u8; HASH_LEN]> {
    if leaves.is_empty() {
        return Err(Error::Invalid("file without chunks"));
    }
    Ok(kdf(
        "sayso/v1/merkle/root",
        &[
            &(leaves.len() as u64).to_be_bytes(),
            &total_cipher.to_be_bytes(),
            &subtree(leaves),
        ],
    ))
}

/// What a receiver without the file key knows about a transfer: enough to
/// check every chunk as it arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub root: [u8; HASH_LEN],
    pub total_cipher: u64,
    pub leaves: Vec<[u8; HASH_LEN]>,
}

impl Manifest {
    /// Accept a leaf list only if it hashes to `root` and its sizes are
    /// consistent with a chunked file.
    pub fn verify(
        root: [u8; HASH_LEN],
        chunks: u64,
        total_cipher: u64,
        leaf_bytes: &[u8],
    ) -> Result<Self> {
        let count = usize::try_from(chunks).map_err(|_| Error::TooLarge)?;
        if count == 0 || count.checked_mul(HASH_LEN) != Some(leaf_bytes.len()) {
            return Err(Error::Malformed("leaf list"));
        }
        // All chunks but the last are full; the last holds between one
        // plaintext byte and a full chunk.
        let full = (chunks - 1)
            .checked_mul(MAX_CIPHER_CHUNK as u64)
            .ok_or(Error::TooLarge)?;
        let last = total_cipher
            .checked_sub(full)
            .ok_or(Error::Invalid("file length"))?;
        if last <= aead::TAG_LEN as u64 || last > MAX_CIPHER_CHUNK as u64 {
            return Err(Error::Invalid("file length"));
        }
        let leaves: Vec<[u8; HASH_LEN]> = leaf_bytes.as_chunks::<HASH_LEN>().0.to_vec();
        if merkle_root(&leaves, total_cipher)? != root {
            return Err(Error::Invalid("leaf list does not match root"));
        }
        Ok(Self {
            root,
            total_cipher,
            leaves,
        })
    }

    pub fn chunks(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The exact length chunk `i` must have.
    pub fn cipher_len(&self, i: u64) -> Result<usize> {
        let chunks = self.chunks();
        if i >= chunks {
            return Err(Error::Invalid("chunk index"));
        }
        if i + 1 < chunks {
            Ok(MAX_CIPHER_CHUNK)
        } else {
            Ok((self.total_cipher - (chunks - 1) * MAX_CIPHER_CHUNK as u64) as usize)
        }
    }

    /// Check one received chunk against its leaf.
    pub fn check_chunk(&self, i: u64, cipher: &[u8]) -> Result<()> {
        if cipher.len() != self.cipher_len(i)? || leaf(cipher) != self.leaves[i as usize] {
            return Err(Error::Invalid("chunk does not match its leaf"));
        }
        Ok(())
    }

    pub fn leaf_bytes(&self) -> Vec<u8> {
        self.leaves.concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn encrypt_all(data: &[u8]) -> (FilePlan, Vec<Vec<u8>>) {
        let plan = FilePlan::for_size(data.len() as u64);
        let chunks = (0..plan.chunks)
            .map(|i| {
                let start = (i as usize * CHUNK).min(data.len());
                let end = start + plan.data_len(i).unwrap();
                encrypt_chunk(&KEY, &plan, i, &data[start..end]).unwrap()
            })
            .collect();
        (plan, chunks)
    }

    fn manifest_of(plan: &FilePlan, chunks: &[Vec<u8>]) -> Manifest {
        let leaves: Vec<_> = chunks.iter().map(|c| leaf(c)).collect();
        let root = merkle_root(&leaves, plan.total_cipher()).unwrap();
        Manifest::verify(root, plan.chunks, plan.total_cipher(), &leaves.concat()).unwrap()
    }

    #[test]
    fn padme_matches_the_reference_points() {
        // Values worked from the definition in the Padmé paper.
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(1000), 1024);
        assert_eq!(padme(1025), 1088);
        assert_eq!(padme(1 << 20), 1 << 20);
        // E = 20, S = 5: the low 15 bits are rounded away.
        assert_eq!(padme((1 << 20) + 1), (1 << 20) + (1 << 15));
    }

    #[test]
    fn padme_overhead_is_bounded_and_monotonic() {
        let mut previous = 0;
        for len in (1u64..5_000_000)
            .step_by(997)
            .chain([u64::MAX / 2, u64::MAX])
        {
            let padded = padme(len);
            assert!(padded >= len);
            assert!(
                padded as f64 <= len as f64 * 1.12 + 1.0,
                "{len} -> {padded}"
            );
            assert!(padded >= previous);
            previous = padded;
        }
    }

    #[test]
    fn plans_cover_edge_sizes() {
        let empty = FilePlan::for_size(0);
        assert_eq!((empty.padded, empty.chunks), (4096, 1));
        assert_eq!(
            (empty.plain_len(0).unwrap(), empty.data_len(0).unwrap()),
            (4096, 0)
        );

        let exact = FilePlan::for_size(CHUNK as u64);
        assert_eq!((exact.padded, exact.chunks), (CHUNK as u64, 1));

        let over = FilePlan::for_size(CHUNK as u64 + 1);
        assert_eq!(over.chunks, 2);
        assert_eq!(over.data_len(1).unwrap(), 1);
        assert_eq!(over.plain_len(1).unwrap(), 1 << 15);
        assert!(over.plain_len(2).is_err());

        // Padding can add a chunk that holds no real data at all.
        let huge = FilePlan::for_size(100 * CHUNK as u64 + 1);
        assert!(huge.chunks > 101);
        assert_eq!(huge.data_len(huge.chunks - 1).unwrap(), 0);
    }

    #[test]
    fn from_parts_rejects_inconsistent_sizes() {
        let plan = FilePlan::for_size(5000);
        assert_eq!(FilePlan::from_parts(5000, plan.padded).unwrap(), plan);
        assert!(FilePlan::from_parts(5000, plan.padded + 1).is_err());
        assert!(FilePlan::from_parts(5000, 10).is_err());
    }

    #[test]
    fn file_round_trip_across_chunks() {
        let data: Vec<u8> = (0..(2 * CHUNK + 12_345))
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let (plan, chunks) = encrypt_all(&data);
        assert_eq!(plan.chunks, 3);
        assert_eq!(
            chunks.iter().map(|c| c.len() as u64).sum::<u64>(),
            plan.total_cipher()
        );
        let mut out = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            out.extend(decrypt_chunk(&KEY, &plan, i as u64, chunk).unwrap());
        }
        assert_eq!(out, data);
    }

    #[test]
    fn chunks_cannot_be_reordered_or_moved_between_files() {
        let data = vec![5u8; 2 * CHUNK];
        let (plan, chunks) = encrypt_all(&data);
        // Same key, same bytes, wrong position.
        assert_eq!(
            decrypt_chunk(&KEY, &plan, 1, &chunks[0]),
            Err(Error::Decrypt)
        );
        // Same position in a file with a different chunk count.
        let other = FilePlan::for_size(3 * CHUNK as u64);
        assert_eq!(
            decrypt_chunk(&KEY, &other, 0, &chunks[0]),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn manifest_checks_each_chunk() {
        let data = vec![9u8; CHUNK + 500];
        let (plan, chunks) = encrypt_all(&data);
        let manifest = manifest_of(&plan, &chunks);
        assert_eq!(manifest.chunks(), 2);
        assert!(manifest.check_chunk(0, &chunks[0]).is_ok());
        assert!(manifest.check_chunk(1, &chunks[1]).is_ok());
        assert!(manifest.check_chunk(1, &chunks[0]).is_err());
        let mut corrupt = chunks[0].clone();
        corrupt[10] ^= 1;
        assert!(manifest.check_chunk(0, &corrupt).is_err());
        assert!(manifest.check_chunk(2, &chunks[0]).is_err());
    }

    #[test]
    fn manifest_rejects_a_leaf_list_that_does_not_match() {
        let (plan, chunks) = encrypt_all(&vec![1u8; 3 * CHUNK]);
        let good = manifest_of(&plan, &chunks);
        let mut leaves = good.leaf_bytes();
        leaves[0] ^= 1;
        assert!(Manifest::verify(good.root, 3, good.total_cipher, &leaves).is_err());
        // Right leaves, wrong claimed sizes.
        let leaves = good.leaf_bytes();
        assert!(Manifest::verify(good.root, 3, good.total_cipher - 1, &leaves).is_err());
        assert!(Manifest::verify(good.root, 2, good.total_cipher, &leaves).is_err());
        assert!(Manifest::verify(good.root, 0, 0, &[]).is_err());
        assert!(Manifest::verify(good.root, u64::MAX, good.total_cipher, &leaves).is_err());
    }

    #[test]
    fn merkle_root_depends_on_order_count_and_length() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let root = |leaves: &[[u8; 32]], total| merkle_root(leaves, total).unwrap();
        assert_ne!(root(&[a, b], 10), root(&[b, a], 10));
        assert_ne!(root(&[a, b], 10), root(&[a, b], 11));
        assert_ne!(root(&[a, b, c], 10), root(&[a, b], 10));
        // A single leaf is not its own root, and an inner node cannot pose as a leaf.
        assert_ne!(root(&[a], 10), a);
        let inner = kdf("sayso/v1/merkle/node", &[&a, &b]);
        assert_ne!(root(&[inner, c], 10), root(&[a, b, c], 10));
        assert!(merkle_root(&[], 0).is_err());
    }

    #[test]
    fn tree_shape_is_rfc_6962() {
        // Five leaves split 4 + 1, and the left four split 2 + 2.
        let l: Vec<[u8; 32]> = (1u8..=5).map(|i| [i; 32]).collect();
        let node = |x: &[u8; 32], y: &[u8; 32]| kdf("sayso/v1/merkle/node", &[x, y]);
        let left = node(&node(&l[0], &l[1]), &node(&l[2], &l[3]));
        assert_eq!(subtree(&l), node(&left, &l[4]));
    }
}
