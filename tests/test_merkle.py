"""Merkle tree tests.

Correctness here is exhaustively cross-validated over small trees rather than
asserted against a handful of copied vectors, because the failure mode that
matters is a proof that verifies when it should not. Every tree size up to
MAX_TREE_SIZE is checked at every index, in both directions.

RFC 6962's own published test vectors should be added on top of this before the
log carries production records.
"""

import hashlib
import unittest

from certifiles.merkle import (
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    root_hash,
    verify_consistency,
    verify_inclusion,
)

MAX_TREE_SIZE = 33


def leaves_for(size: int) -> list[bytes]:
    return [leaf_hash(f"record-{i}".encode()) for i in range(size)]


class TestHashing(unittest.TestCase):
    def test_empty_tree_is_sha256_of_empty_string(self):
        self.assertEqual(root_hash([]), hashlib.sha256(b"").digest())

    def test_single_leaf_tree_root_is_the_leaf(self):
        leaf = leaf_hash(b"only")
        self.assertEqual(root_hash([leaf]), leaf)

    def test_leaf_and_interior_hashes_are_domain_separated(self):
        # Without the prefix bytes an attacker could present an interior node as
        # a leaf, claiming a whole subtree was a single record. This is the
        # classic Merkle second-preimage attack.
        pair = leaf_hash(b"a") + leaf_hash(b"b")
        self.assertNotEqual(leaf_hash(pair), node_hash(leaf_hash(b"a"), leaf_hash(b"b")))

    def test_distinct_leaf_sets_give_distinct_roots(self):
        roots = {root_hash(leaves_for(n)) for n in range(1, MAX_TREE_SIZE)}
        self.assertEqual(len(roots), MAX_TREE_SIZE - 1)


class TestInclusion(unittest.TestCase):
    def test_every_index_of_every_tree_size_verifies(self):
        for size in range(1, MAX_TREE_SIZE):
            leaves = leaves_for(size)
            root = root_hash(leaves)
            for index in range(size):
                proof = inclusion_proof(leaves, index)
                with self.subTest(size=size, index=index):
                    self.assertTrue(
                        verify_inclusion(leaves[index], index, size, proof, root)
                    )

    def test_proof_length_is_logarithmic(self):
        for size in range(1, MAX_TREE_SIZE):
            leaves = leaves_for(size)
            for index in range(size):
                proof = inclusion_proof(leaves, index)
                self.assertLessEqual(len(proof), max(1, size - 1).bit_length())

    def test_wrong_index_is_rejected(self):
        size = 16
        leaves = leaves_for(size)
        root = root_hash(leaves)
        proof = inclusion_proof(leaves, 5)
        for index in range(size):
            if index == 5:
                continue
            with self.subTest(index=index):
                self.assertFalse(
                    verify_inclusion(leaves[5], index, size, proof, root)
                )

    def test_tampered_proof_node_is_rejected(self):
        leaves = leaves_for(16)
        root = root_hash(leaves)
        for index in range(16):
            proof = inclusion_proof(leaves, index)
            for position in range(len(proof)):
                corrupted = list(proof)
                corrupted[position] = leaf_hash(b"forged")
                with self.subTest(index=index, position=position):
                    self.assertFalse(
                        verify_inclusion(leaves[index], index, 16, corrupted, root)
                    )

    def test_leaf_not_in_tree_is_rejected(self):
        leaves = leaves_for(16)
        root = root_hash(leaves)
        proof = inclusion_proof(leaves, 7)
        self.assertFalse(
            verify_inclusion(leaf_hash(b"never registered"), 7, 16, proof, root)
        )

    def test_truncated_and_extended_proofs_are_rejected(self):
        leaves = leaves_for(16)
        root = root_hash(leaves)
        proof = inclusion_proof(leaves, 9)
        self.assertFalse(verify_inclusion(leaves[9], 9, 16, proof[:-1], root))
        self.assertFalse(
            verify_inclusion(leaves[9], 9, 16, proof + [leaf_hash(b"x")], root)
        )

    def test_index_beyond_tree_is_rejected(self):
        leaves = leaves_for(8)
        root = root_hash(leaves)
        self.assertFalse(verify_inclusion(leaves[0], 8, 8, [], root))
        self.assertFalse(verify_inclusion(leaves[0], 99, 8, [], root))

    def test_malformed_proof_nodes_are_rejected(self):
        # The explicit length guard in verify_inclusion is defence in depth, not
        # the thing doing the work here: a wrong-length node already fails the
        # final root comparison. Mutation testing confirmed removing the guard
        # does not change any outcome. Keep it for fail-fast clarity, but the
        # property under test is the rejection, not the guard.
        leaves = leaves_for(8)
        root = root_hash(leaves)
        proof = inclusion_proof(leaves, 3)
        for bad_node in (b"", b"short", b"\x00" * 64):
            with self.subTest(length=len(bad_node)):
                self.assertFalse(
                    verify_inclusion(leaves[3], 3, 8, [bad_node] + proof[1:], root)
                )


class TestConsistency(unittest.TestCase):
    def test_every_growth_step_verifies(self):
        for new_size in range(1, MAX_TREE_SIZE):
            new_leaves = leaves_for(new_size)
            new_root = root_hash(new_leaves)
            for old_size in range(1, new_size + 1):
                old_root = root_hash(new_leaves[:old_size])
                proof = consistency_proof(new_leaves, old_size)
                with self.subTest(old=old_size, new=new_size):
                    self.assertTrue(
                        verify_consistency(
                            old_size, new_size, proof, old_root, new_root
                        )
                    )

    def test_forked_log_is_detected(self):
        # The attack ADR 0001 exists to stop: the operator keeps two histories
        # that share a prefix, serving a different one to different parties.
        shared = 12
        branch_a = leaves_for(shared) + [leaf_hash(b"entry-A")]
        branch_b = leaves_for(shared) + [leaf_hash(b"entry-B")]
        old_root = root_hash(leaves_for(shared))

        proof_a = consistency_proof(branch_a, shared)
        self.assertTrue(
            verify_consistency(
                shared, len(branch_a), proof_a, old_root, root_hash(branch_a)
            )
        )
        # Branch A's proof must not verify against branch B's root.
        self.assertFalse(
            verify_consistency(
                shared, len(branch_b), proof_a, old_root, root_hash(branch_b)
            )
        )

    def test_rewritten_history_is_detected(self):
        # An entry altered in place, with the tree size left unchanged.
        original = leaves_for(20)
        rewritten = list(original)
        rewritten[4] = leaf_hash(b"substituted after the fact")
        old_root = root_hash(original[:10])
        proof = consistency_proof(original, 10)
        self.assertFalse(
            verify_consistency(10, 20, proof, old_root, root_hash(rewritten))
        )

    def test_shrinking_tree_is_rejected(self):
        leaves = leaves_for(16)
        proof = consistency_proof(leaves, 8)
        self.assertFalse(
            verify_consistency(
                16, 8, proof, root_hash(leaves), root_hash(leaves[:8])
            )
        )

    def test_same_size_requires_matching_root_and_empty_proof(self):
        leaves = leaves_for(8)
        root = root_hash(leaves)
        self.assertTrue(verify_consistency(8, 8, [], root, root))
        self.assertFalse(verify_consistency(8, 8, [], root, leaf_hash(b"other")))
        self.assertFalse(verify_consistency(8, 8, [root], root, root))

    def test_tampered_consistency_proof_is_rejected(self):
        leaves = leaves_for(24)
        new_root = root_hash(leaves)
        for old_size in range(1, 24):
            old_root = root_hash(leaves[:old_size])
            proof = consistency_proof(leaves, old_size)
            for position in range(len(proof)):
                corrupted = list(proof)
                corrupted[position] = leaf_hash(b"forged")
                with self.subTest(old=old_size, position=position):
                    self.assertFalse(
                        verify_consistency(
                            old_size, 24, corrupted, old_root, new_root
                        )
                    )

    def test_malformed_consistency_proof_nodes_are_rejected(self):
        leaves = leaves_for(16)
        old_root = root_hash(leaves[:9])
        proof = consistency_proof(leaves, 9)
        for bad_node in (b"", b"short", b"\x00" * 64):
            for position in range(len(proof)):
                corrupted = list(proof)
                corrupted[position] = bad_node
                with self.subTest(length=len(bad_node), position=position):
                    self.assertFalse(
                        verify_consistency(
                            9, 16, corrupted, old_root, root_hash(leaves)
                        )
                    )

    def test_wrong_old_root_is_rejected(self):
        leaves = leaves_for(16)
        proof = consistency_proof(leaves, 9)
        self.assertFalse(
            verify_consistency(
                9, 16, proof, leaf_hash(b"not the old root"), root_hash(leaves)
            )
        )


if __name__ == "__main__":
    unittest.main()
