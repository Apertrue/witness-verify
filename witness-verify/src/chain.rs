//! The v2 window chain, natively: the exact field assembly the app's
//! `WindowChain.swift` uses, so a head computed here is the head the app,
//! the service and the page compute.

use crate::poseidon2;
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use sha2::{Digest, Sha256};

/// Bits compared per window: 146 chunks of 224 bits.
pub const NCHUNK: usize = 146;
pub const PACK: usize = 224;
pub const NBITS: usize = NCHUNK * PACK;
/// The cap on every camera's line: an enrolled limit is never above this.
/// Fewer mismatched bits than a camera's own limit is a pass.
pub const TAU: u64 = 15534;
/// The lowest limit an enrolment may commit (a line of zero passes nothing).
pub const MIN_LIMIT: u64 = 1;

/// Whether a camera's enrolled limit is one the proofs accept:
/// `MIN_LIMIT <= limit <= TAU` (spec/PER_CAMERA_THRESHOLD.md).
pub fn limit_ok(limit: u64) -> bool {
    (MIN_LIMIT..=TAU).contains(&limit)
}

/// One packed chunk: 28 bytes, read big-endian as a field element.
pub type Chunk = [u8; 28];

pub(crate) fn tag(ascii: &str) -> Fr {
    let mut be = [0u8; 32];
    be[32 - ascii.len()..].copy_from_slice(ascii.as_bytes());
    field_be(&be)
}

pub fn init_tag() -> Fr {
    tag("witness-window-chain-v3:init")
}
pub fn link_tag() -> Fr {
    tag("witness-window-chain-v3:link")
}
pub fn fold_tag() -> Fr {
    tag("witness-window-chain-v3:fold")
}

/// The v2 tags, kept so the shared v2 vectors stay checkable and a v2
/// head can still be recomputed by anything that needs to read one.
pub fn init_tag_v2() -> Fr {
    tag("witness-window-chain-v2:init")
}
pub fn link_tag_v2() -> Fr {
    tag("witness-window-chain-v2:link")
}
pub fn fold_tag_v2() -> Fr {
    tag("witness-window-chain-v2:fold")
}

/// The picture root's tag: one picture's hash folded into a window's root.
pub fn picture_tag() -> Fr {
    tag("witness-window-picture-v1")
}

/// A picture's SHA-256 as a field: the low 248 bits, so the value is
/// canonical whatever the hash's top byte says. The app reduces the same
/// way (`WindowChain.pictureHashField`).
pub fn picture_hash_field(sha256: &[u8; 32]) -> Fr {
    let mut be = *sha256;
    be[0] = 0;
    field_be(&be)
}

/// A window's picture root: the running Poseidon2 fold of its pictures'
/// hashes in capture order, from zero. Zero when the window carried none.
/// A reader holding the pictures folds the same way and must land on the
/// root the link carries (spec/COMMIT_AND_DELIVER.md).
pub fn picture_root(hashes: &[Fr]) -> Fr {
    let mut r = Fr::ZERO;
    for h in hashes {
        r = poseidon2::hash(&[picture_tag(), r, *h]);
    }
    r
}

/// A 32-byte big-endian integer as a field element, or None when it is
/// not a canonical element: the check for bytes that arrived over a wire.
pub fn try_field_be(be: &[u8; 32]) -> Option<Fr> {
    let mut le = *be;
    le.reverse();
    Option::<Fr>::from(Fr::from_bytes(&le))
}

/// A 32-byte big-endian integer as a field element. For values this crate
/// made itself (tags, digests); wire bytes go through `try_field_be`.
pub fn field_be(be: &[u8; 32]) -> Fr {
    try_field_be(be).expect("canonical field element")
}

pub fn field_to_be(f: &Fr) -> [u8; 32] {
    let mut b = f.to_bytes();
    b.reverse();
    b
}

/// The chunk as the chain hashes it: left-padded to 32 bytes, big-endian.
pub fn chunk_field(c: &Chunk) -> Fr {
    let mut be = [0u8; 32];
    be[4..].copy_from_slice(c);
    field_be(&be)
}

/// Bit `j` of the chunk's integer value (Noir's `to_le_bits` order).
pub fn chunk_bit(c: &Chunk, j: usize) -> bool {
    (c[27 - j / 8] >> (j % 8)) & 1 == 1
}

pub fn chunk_bits(c: &Chunk) -> impl Iterator<Item = bool> + '_ {
    (0..PACK).map(move |j| chunk_bit(c, j))
}

/// The 16-byte chain id as a field, big-endian.
pub fn chain_id_field(id: &[u8; 16]) -> Fr {
    let mut be = [0u8; 32];
    be[16..].copy_from_slice(id);
    field_be(&be)
}

/// The window header: index in bits 80.., frames in 16..64, passed at 8,
/// degenerate at 0.
pub fn header(index: u64, frames: u64, passed: bool, degenerate: bool) -> Fr {
    Fr::from(index) * Fr::from_u128(1u128 << 80)
        + Fr::from(frames) * Fr::from(1u64 << 16)
        + Fr::from(passed as u64) * Fr::from(256)
        + Fr::from(degenerate as u64)
}

/// The chain's genesis head: the enrolment the stream compares against.
pub fn genesis(chain_id: Fr, enrolled: &[Chunk]) -> Fr {
    let mut fields = Vec::with_capacity(2 + enrolled.len());
    fields.push(init_tag());
    fields.push(chain_id);
    fields.extend(enrolled.iter().map(chunk_field));
    poseidon2::hash(&fields)
}

/// The v2 genesis, for reading v2 chains.
pub fn genesis_v2(chain_id: Fr, enrolled: &[Chunk]) -> Fr {
    let mut fields = Vec::with_capacity(2 + enrolled.len());
    fields.push(init_tag_v2());
    fields.push(chain_id);
    fields.extend(enrolled.iter().map(chunk_field));
    poseidon2::hash(&fields)
}

/// The enrolment commitment's tag, so `C` can never be read as a chain
/// digest, a registry node, or a leaf.
pub fn commit_tag() -> Fr {
    tag("witness-enrolment-v4:commit")
}

/// `C`: what the receipts pin and what the registry leaf embeds.
///
/// ```text
/// C = P2(commit_tag, registry_domain, chunks.., limit, nonce)
/// ```
///
/// Four inputs beyond the bits, each doing one job. The `limit` is this
/// camera's own line (spec/PER_CAMERA_THRESHOLD.md): committed here so the
/// batch proofs judge every window against it, and never published. The tag separates
/// this hash from every other Poseidon2 hash in the system. The
/// `registry_domain` makes the same sensor's `C` differ between
/// registries even if an app bug reused a nonce, so two services
/// comparing notes learn nothing. The `nonce`, fresh per enrolment, is
/// what lets `C` die on rotation: the bits behind it cannot change, so
/// without it a retired enrolment would leave a permanent handle.
pub fn enrolment_commitment(enrolled: &[Chunk], limit: u64, registry_domain: Fr, nonce: Fr) -> Fr {
    let mut fields = Vec::with_capacity(4 + enrolled.len());
    fields.push(commit_tag());
    fields.push(registry_domain);
    fields.extend(enrolled.iter().map(chunk_field));
    fields.push(Fr::from(limit));
    fields.push(nonce);
    poseidon2::hash(&fields)
}

/// The registry domain for a registry id: SHA-256 of the id, top byte
/// cleared so the value is always in the field.
///
/// A hash rather than the string itself because the id is arbitrary
/// text and the circuit takes a field element; cleared rather than
/// reduced because a modular reduction would map two ids to one domain
/// only in theory, but the clear is exact and free.
pub fn registry_domain(registry_id: &str) -> Fr {
    let mut be: [u8; 32] = Sha256::digest(registry_id.as_bytes()).into();
    be[0] &= 0x1f;
    field_be(&be)
}

/// The v3 link: the picture root sits beside the header, before the bits.
pub fn link_digest(chain_id: Fr, header: Fr, picture_root: Fr, fresh: &[Chunk]) -> Fr {
    let mut fields = Vec::with_capacity(4 + fresh.len());
    fields.push(link_tag());
    fields.push(chain_id);
    fields.push(header);
    fields.push(picture_root);
    fields.extend(fresh.iter().map(chunk_field));
    poseidon2::hash(&fields)
}

/// The v2 link, for reading v2 chains.
pub fn link_digest_v2(chain_id: Fr, header: Fr, fresh: &[Chunk]) -> Fr {
    let mut fields = Vec::with_capacity(3 + fresh.len());
    fields.push(link_tag_v2());
    fields.push(chain_id);
    fields.push(header);
    fields.extend(fresh.iter().map(chunk_field));
    poseidon2::hash(&fields)
}

pub fn fold(head: Fr, digest: Fr) -> Fr {
    poseidon2::hash(&[fold_tag(), head, digest])
}

/// The v2 fold, for reading v2 chains.
pub fn fold_v2(head: Fr, digest: Fr) -> Fr {
    poseidon2::hash(&[fold_tag_v2(), head, digest])
}

pub fn mismatch(fresh: &[Chunk], enrolled: &[Chunk]) -> u64 {
    let mut n = 0u64;
    for c in 0..NCHUNK {
        for (a, b) in chunk_bits(&fresh[c]).zip(chunk_bits(&enrolled[c])) {
            n += (a ^ b) as u64;
        }
    }
    n
}

/// One window as the app hands it over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub chain_id: [u8; 16],
    pub window_index: u64,
    pub frames: u64,
    pub degenerate: bool,
    /// The window's picture root, big-endian; all zero when the window
    /// carried no picture. Must be a canonical field element: the FFI
    /// checks, the prover trusts its own.
    pub picture_root: [u8; 32],
    pub fresh: Vec<Chunk>,
}

/// What the honest prover derives for one window.
#[derive(Clone, Debug)]
pub struct Derived {
    pub mismatch: u64,
    pub passed: bool,
    pub header: Fr,
    pub digest: Fr,
    pub head_out: Fr,
}

pub fn derive(w: &Window, enrolled: &[Chunk], limit: u64, head_in: Fr) -> Derived {
    assert_eq!(w.fresh.len(), NCHUNK, "a window carries {NCHUNK} chunks");
    assert_eq!(
        enrolled.len(),
        NCHUNK,
        "an enrolment carries {NCHUNK} chunks"
    );
    let mismatch = mismatch(&w.fresh, enrolled);
    // One verdict: under this camera's committed line AND not a degenerate
    // (blank or frozen) feed, exactly as the camera extension decides.
    let passed = mismatch < limit && !w.degenerate;
    let header = header(w.window_index, w.frames, passed, w.degenerate);
    let picture_root = field_be(&w.picture_root);
    let digest = link_digest(chain_id_field(&w.chain_id), header, picture_root, &w.fresh);
    let head_out = fold(head_in, digest);
    Derived {
        mismatch,
        passed,
        header,
        digest,
        head_out,
    }
}

#[cfg(test)]
pub(crate) mod vectors {
    //! The shared vectors the Swift, Python and JS chains are pinned to
    //! (WindowChainV2Tests.swift), produced by the independent Python
    //! reference.
    use super::*;

    pub fn chain_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        id
    }

    pub fn make_chunks(mul_c: usize, mul_j: usize, add: usize) -> Vec<Chunk> {
        (0..NCHUNK)
            .map(|c| {
                let mut d = [0u8; 28];
                for (j, b) in d.iter_mut().enumerate() {
                    *b = ((c * mul_c + j * mul_j + add) % 256) as u8;
                }
                d
            })
            .collect()
    }

    pub fn enrolled() -> Vec<Chunk> {
        make_chunks(7, 13, 1)
    }
    pub fn window() -> Vec<Chunk> {
        make_chunks(11, 3, 5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_be(f: &Fr) -> String {
        hex::encode(field_to_be(f))
    }

    #[test]
    fn v2_genesis_matches_the_shared_vector() {
        let g = genesis_v2(chain_id_field(&vectors::chain_id()), &vectors::enrolled());
        assert_eq!(
            hex_be(&g),
            "0691beee4773c6a9349b082ca3dd88715436b335752a39b952b3daf344869786"
        );
    }

    #[test]
    fn v2_link_and_fold_match_the_shared_vector() {
        let id = chain_id_field(&vectors::chain_id());
        let head = genesis_v2(id, &vectors::enrolled());
        let digest = link_digest_v2(id, header(0, 24, true, false), &vectors::window());
        assert_eq!(
            hex_be(&digest),
            "249618ffacba359b95501b1fcdcd2c8aba7add947a5da50b91842a3f8b3aebab"
        );
        assert_eq!(
            hex_be(&fold_v2(head, digest)),
            "1d8a8382933182cae7fd388b9e884a6b1909757d5833cd2c9f17fbef61465b45"
        );
    }

    /// The v3 vectors, shared with WindowChainV3Tests.swift: the same
    /// chunks and chain id as v2, a window with no picture, and a window
    /// whose two pictures are the ASCII strings "picture-0" and
    /// "picture-1". Produced here and by WindowChainV3Tests.swift
    /// independently on 13 Sep 2026; the two agreed on every value.
    #[test]
    fn v3_vectors() {
        let id = chain_id_field(&vectors::chain_id());
        let head = genesis(id, &vectors::enrolled());
        let none = link_digest(id, header(0, 24, true, false), Fr::ZERO, &vectors::window());
        let head1 = fold(head, none);
        let h0: [u8; 32] = Sha256::digest(b"picture-0").into();
        let h1: [u8; 32] = Sha256::digest(b"picture-1").into();
        let root = picture_root(&[picture_hash_field(&h0), picture_hash_field(&h1)]);
        let two = link_digest(id, header(1, 24, true, false), root, &vectors::window());
        let head2 = fold(head1, two);
        assert_eq!(
            hex_be(&head),
            "037e598cc347457a840037bf871b16d2a6dafa472547e88335fb330bc5421ae8"
        );
        assert_eq!(
            hex_be(&none),
            "1e0f01407e7b169498de160f0ab6cbfa227bad82650e11dadd3f772d6af402d9"
        );
        assert_eq!(
            hex_be(&head1),
            "06e0db022703f1438970fd365a776b2901b31162d898948d053cb9cceb014b1d"
        );
        assert_eq!(
            hex_be(&root),
            "0df5bf57bae7a9f482bf6bcb1723c4c5d8545045b8500d371185373ce588d33a"
        );
        assert_eq!(
            hex_be(&two),
            "12154e0e5eab1a6b5de575f468721b6cc81d0037a362500cee97b2a5726b6ecf"
        );
        assert_eq!(
            hex_be(&head2),
            "0f4addaa342dd3a9b2c329b33daa14e44b18b995a68d92d3249a9c6c90b8cd0d"
        );
        assert_eq!(picture_root(&[]), Fr::ZERO);
    }

    #[test]
    fn chunk_bits_are_the_integer_bits() {
        let mut c = [0u8; 28];
        c[27] = 0b0000_0101; // integer value 5: bits 0 and 2
        c[0] = 0x80; // the top bit of the 224-bit integer
        assert!(chunk_bit(&c, 0) && !chunk_bit(&c, 1) && chunk_bit(&c, 2));
        assert!(chunk_bit(&c, 223));
        let f = chunk_field(&c);
        let le = f.to_bytes();
        assert_eq!(le[0], 5);
        assert_eq!(le[27], 0x80);
        assert_eq!(le[28..], [0, 0, 0, 0]);
    }

    #[test]
    fn identical_chunks_have_no_mismatch_and_inverted_ones_mismatch_everywhere() {
        let e = vectors::enrolled();
        assert_eq!(mismatch(&e, &e), 0);
        let inv: Vec<Chunk> = e.iter().map(|c| c.map(|b| !b)).collect();
        assert_eq!(mismatch(&inv, &e), NBITS as u64);
    }
}
