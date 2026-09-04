"""RFC 6962 Merkle tree operations.

The transparency log's append-only guarantee rests entirely on these functions.
A defect here is unrecoverable in the way described in ADR 0001: records issued
against a broken tree cannot be re-proven later, because the proofs clients
already hold would have to change.

Leaf and interior hashes are domain-separated by a prefix byte so that a leaf
can never be reinterpreted as an interior node, which would otherwise let an
attacker present a subtree as a single record.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

HASH_SIZE = hashlib.sha256().digest_size


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split_point(size: int) -> int:
    """Largest power of two strictly less than size.

    RFC 6962 splits every subtree here rather than at the midpoint, which is
    what makes the left subtree always complete and lets proofs stay stable as
    the tree grows.
    """
    if size < 2:
        raise ValueError("split point is undefined for sizes below 2")
    return 1 << (size - 1).bit_length() - 1


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash over already-hashed leaves."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split_point(len(leaves))
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(leaves):
        raise IndexError(f"index {index} outside tree of size {len(leaves)}")
    if len(leaves) == 1:
        return []
    k = _split_point(len(leaves))
    if index < k:
        return inclusion_proof(leaves[:k], index) + [root_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [root_hash(leaves[:k])]


def consistency_proof(leaves: Sequence[bytes], old_size: int) -> list[bytes]:
    """Proof that a tree of old_size is a prefix of the tree over leaves.

    This is the proof a witness checks before cosigning, and it is the only
    thing standing between the operator and a forked log.
    """
    if not 0 < old_size <= len(leaves):
        raise ValueError(f"old_size {old_size} outside 1..{len(leaves)}")
    return _subproof(leaves, old_size, True)


def _subproof(leaves: Sequence[bytes], old_size: int, is_complete: bool) -> list[bytes]:
    if old_size == len(leaves):
        # The old tree is this whole subtree. Its root is only needed when the
        # caller cannot already derive it from the old checkpoint.
        return [] if is_complete else [root_hash(leaves)]
    k = _split_point(len(leaves))
    if old_size <= k:
        return _subproof(leaves[:k], old_size, is_complete) + [root_hash(leaves[k:])]
    return _subproof(leaves[k:], old_size - k, False) + [root_hash(leaves[:k])]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """Verify that leaf sits at index in a tree of tree_size with the given root.

    Returns False rather than raising on malformed input. Callers are verifying
    untrusted data, and an exception path is a place to forget a check.
    """
    if index >= tree_size or tree_size < 1:
        return False
    if any(len(node) != HASH_SIZE for node in proof):
        return False

    node_index = index
    last_index = tree_size - 1
    computed = leaf

    for sibling in proof:
        if last_index == 0:
            return False
        if node_index % 2 == 1 or node_index == last_index:
            computed = node_hash(sibling, computed)
            while node_index != 0 and node_index % 2 == 0:
                node_index >>= 1
                last_index >>= 1
        else:
            computed = node_hash(computed, sibling)
        node_index >>= 1
        last_index >>= 1

    return last_index == 0 and computed == root


def verify_consistency(
    old_size: int,
    new_size: int,
    proof: Sequence[bytes],
    old_root: bytes,
    new_root: bytes,
) -> bool:
    """Verify the tree at new_size still contains the tree at old_size unchanged.

    A False here is the `COMPROMISED` verifier outcome in ADR 0001: it is
    evidence the log forked or rewrote history, not a transient error.
    """
    if old_size > new_size or old_size < 0:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof
    if any(len(node) != HASH_SIZE for node in proof):
        return False

    node_index = old_size - 1
    last_index = new_size - 1
    # Shift past the right-hand edge of the old tree: a complete left subtree
    # contributes no proof node because the verifier can derive it.
    while node_index % 2 == 1:
        node_index >>= 1
        last_index >>= 1

    proof = list(proof)
    if node_index == 0:
        old_computed = new_computed = old_root
        remaining = proof
    else:
        if not proof:
            return False
        old_computed = new_computed = proof[0]
        remaining = proof[1:]

    for sibling in remaining:
        if last_index == 0:
            return False
        if node_index % 2 == 1 or node_index == last_index:
            old_computed = node_hash(sibling, old_computed)
            new_computed = node_hash(sibling, new_computed)
            while node_index != 0 and node_index % 2 == 0:
                node_index >>= 1
                last_index >>= 1
        else:
            new_computed = node_hash(new_computed, sibling)
        node_index >>= 1
        last_index >>= 1

    return last_index == 0 and old_computed == old_root and new_computed == new_root
