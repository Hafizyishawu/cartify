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
EMPTY_ROOT = hashlib.sha256(b"").digest()


def _is_hash(value: object) -> bool:
    return isinstance(value, (bytes, bytearray)) and len(value) == HASH_SIZE


def _is_index(value: object) -> bool:
    # bool is an int subclass; accepting True as index 1 would let a type
    # confusion upstream become a silent off-by-one here.
    return isinstance(value, int) and not isinstance(value, bool)


def _inclusion_proof_length(index: int, size: int) -> int:
    """Number of nodes a well-formed inclusion proof must have.

    Binding the proof to the tree size means a proof cannot be presented
    against a size it was not issued for.
    """
    if size == 1:
        return 0
    k = _split_point(size)
    if index < k:
        return 1 + _inclusion_proof_length(index, k)
    return 1 + _inclusion_proof_length(index - k, size - k)


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
    if not _is_index(index) or not _is_index(tree_size):
        return False
    # A negative index is not merely out of range: Python's -1 % 2 == 1 makes it
    # walk the all-right-siblings path, so it aliases the last index whenever
    # that index is all ones in binary, and the function would return True for a
    # false statement.
    if tree_size < 1 or not 0 <= index < tree_size:
        return False
    if not _is_hash(leaf) or not _is_hash(root):
        return False
    try:
        nodes = list(proof)
    except TypeError:
        return False
    if not all(_is_hash(node) for node in nodes):
        return False
    if len(nodes) != _inclusion_proof_length(index, tree_size):
        return False
    proof = nodes

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
    if not _is_index(old_size) or not _is_index(new_size):
        return False
    if not _is_hash(old_root) or not _is_hash(new_root):
        return False
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    try:
        nodes = list(proof)
    except TypeError:
        return False
    if not all(_is_hash(node) for node in nodes):
        return False
    if old_size == new_size:
        return not nodes and old_root == new_root
    if old_size == 0:
        # An empty prefix is consistent with any tree, but only if the caller's
        # old_root really is the empty-tree root. Returning True for an
        # arbitrary old_root would give a witness bootstrapping from zero the
        # same answer for "verified" and "checked nothing", and it would cosign
        # whatever the operator offered.
        return not nodes and old_root == EMPTY_ROOT
    proof = nodes

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
