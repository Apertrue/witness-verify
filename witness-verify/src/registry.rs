//! The device registry's Merkle tree, Poseidon2 edition (registry v3).
//!
//! The leaf is built over the CANCELABLE TEMPLATE, which is what makes
//! it non-invertible, rotatable and uncorrelated between registries,
//! with the enrolment commitment `C` bound in beside it:
//!
//! ```text
//! leaf = P2(leaf_tag, template_chunks.., C)
//! ```
//!
//! `C` is what the batch receipts pin, so a leaf carries both halves of
//! the story: the identity the registry manages, and the measurements
//! the receipts prove. Neither is derivable from the leaf. The join is
//! made in the membership circuit, which proves this leaf sits under a
//! signed root while publishing only a per-call blinding of `C`.
//!
//! Everything here is domain-tagged, so a node can never be read as a
//! leaf, a leaf as a chain digest, or either as anything else the
//! system hashes with Poseidon2.
use crate::chain::{tag, Chunk};
use crate::poseidon2;
use ff::Field;
use halo2curves::bn256::Fr;

/// Depth 20 = 1,048,576 devices, matching the v1 registry's choice.
pub const DEPTH: usize = 20;

/// The interior-node tag: `node = H(tag, left, right)`.
pub fn node_tag() -> Fr {
    tag("witness-registry-v3:node")
}

/// The leaf tag.
pub fn leaf_tag() -> Fr {
    tag("witness-registry-v3:leaf")
}

/// One interior node.
pub fn node(left: Fr, right: Fr) -> Fr {
    poseidon2::hash(&[node_tag(), left, right])
}

/// The leaf for an enrolment: its cancelable template, with the
/// commitment the receipts pin bound in beside it.
///
/// `template` is the transform's output, packed exactly as the raw
/// chunks are. `commitment` is `chain::enrolment_commitment` over the
/// RAW chunks of the same enrolment. The service computes this itself
/// at enrolment; a client-supplied leaf is refused, as it always was.
pub fn leaf(template: &[Chunk], commitment: Fr) -> Fr {
    let mut fields = Vec::with_capacity(2 + template.len());
    fields.push(leaf_tag());
    fields.extend(template.iter().map(crate::chain::chunk_field));
    fields.push(commitment);
    poseidon2::hash(&fields)
}

/// The empty-subtree chain: `EMPTY[0] = 0`, `EMPTY[i+1] = node(E, E)`.
pub fn empty() -> [Fr; DEPTH + 1] {
    let mut out = [Fr::ZERO; DEPTH + 1];
    for i in 0..DEPTH {
        out[i + 1] = node(out[i], out[i]);
    }
    out
}

/// Walks a path from `leaf` at `index` to the root. None when the index
/// is outside the tree's address space: the walk reads only the low
/// DEPTH bits, so a larger index would silently alias a valid location.
pub fn root_from_path(leaf: Fr, index: u64, siblings: &[Fr; DEPTH]) -> Option<Fr> {
    if index >= 1u64 << DEPTH {
        return None;
    }
    let mut acc = leaf;
    for (i, sib) in siblings.iter().enumerate() {
        acc = if (index >> i) & 1 == 1 {
            node(*sib, acc)
        } else {
            node(acc, *sib)
        };
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{enrolment_commitment, field_to_be};

    fn hex(f: &Fr) -> String {
        field_to_be(f).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_empty_tree_and_a_first_leaf_are_pinned() {
        let empty = empty();
        // Known-answer values: any reimplementation (the service's helper,
        // the page's wasm) must reproduce these exactly.
        // Known-answer values: any reimplementation (the service's
        // helper, the page's wasm) must reproduce these exactly.
        assert_eq!(
            hex(&empty[1]),
            "0b9c0450731b2b7a06ec8823d6334cc29cd4d86822f064d796de25bf8b5eb95f"
        );
        assert_eq!(
            hex(&empty[DEPTH]),
            "01d6cc0557ae36d820cf8a3726168952db00355325728c92e7d9efbf21a8152c"
        );
        let enrolled: Vec<Chunk> = (0..crate::NCHUNK)
            .map(|c| std::array::from_fn(|j| ((c * 7 + j * 13 + 1) % 256) as u8))
            .collect();
        let commitment =
            crate::chain::enrolment_commitment(&enrolled, crate::chain::TAU, Fr::ZERO, Fr::ZERO);
        let l = leaf(&enrolled, commitment);
        let mut sibs = [Fr::ZERO; DEPTH];
        sibs.copy_from_slice(&empty[..DEPTH]);
        let root = root_from_path(l, 0, &sibs).unwrap();
        assert_eq!(
            hex(&l),
            "21139d1447f45bb7225c68d5a9a734e114329a37a4cd9aded0f68d31c58565a1"
        );
        assert_eq!(
            hex(&root),
            "1f8d614bdbd4a2e0548cf8df971dbbee8f41bb4d7f9badf5e16356563bf0c15a"
        );
        // The right sibling chain reproduces an insert-at-0 tree.
        assert_ne!(root, empty[DEPTH]);
        // An index that flips one direction changes the root.
        assert_ne!(root_from_path(l, 1, &sibs).unwrap(), root);
        // The address space's edges: the largest valid index walks, the
        // first invalid one is refused rather than aliased to index 0.
        assert!(root_from_path(l, (1 << DEPTH) - 1, &sibs).is_some());
        assert!(root_from_path(l, 1 << DEPTH, &sibs).is_none());
    }

    #[test]
    fn a_leaf_binds_both_halves_and_separates_its_domains() {
        let template: Vec<Chunk> = (0..crate::NCHUNK)
            .map(|c| std::array::from_fn(|j| ((c * 7 + j * 13 + 1) % 256) as u8))
            .collect();
        let raw: Vec<Chunk> = (0..crate::NCHUNK)
            .map(|c| std::array::from_fn(|j| ((c * 11 + j * 5 + 3) % 256) as u8))
            .collect();
        let d = Fr::from(42u64);
        let n = Fr::from(7777u64);
        let c = enrolment_commitment(&raw, crate::chain::TAU, d, n);

        // Both halves are load-bearing: change either and the leaf moves.
        let mut other_template = template.clone();
        other_template[0][0] ^= 1;
        assert_ne!(leaf(&template, c), leaf(&other_template, c));
        assert_ne!(leaf(&template, c), leaf(&template, c + Fr::ONE));

        // Rotation: a fresh nonce gives a fresh commitment and leaf, so
        // nothing about the retired enrolment carries forward.
        let rotated = enrolment_commitment(&raw, crate::chain::TAU, d, n + Fr::ONE);
        assert_ne!(rotated, c);
        assert_ne!(leaf(&template, rotated), leaf(&template, c));

        // Cross-registry: the same sensor in another registry commits to
        // a different value even under a reused nonce.
        assert_ne!(
            enrolment_commitment(&raw, crate::chain::TAU, d + Fr::ONE, n),
            c
        );

        // The limit is committed: another line is another commitment.
        assert_ne!(enrolment_commitment(&raw, crate::chain::TAU - 1, d, n), c);

        // A leaf is never a node, and never the commitment it carries.
        assert_ne!(leaf(&template, c), node(c, c));
        assert_ne!(leaf(&template, c), c);
    }
}
