"""Near-match search tests.

The costs here are asymmetric: a missed match is an annoyance, a false positive
is an accusation handed to someone who did nothing. So most of these check that
something is *not* promoted rather than that it is found.
"""

import unittest

from certifiles.fingerprint import (
    LOW_QUALITY_CEILING,
    Fingerprint,
    FingerprintError,
    FingerprintKind,
    normalised_distance,
    validate_quality,
)
from certifiles.nearmatch import (
    AlertPolicy,
    Band,
    NearMatchError,
    NearMatchIndex,
    classify,
    monitor,
)

PHASH = FingerprintKind.PHASH
DHASH = FingerprintKind.DHASH
PDQ = FingerprintKind.PDQ


def phash(value: str) -> Fingerprint:
    return Fingerprint(PHASH, value)


def flip(value: str, bits: int) -> str:
    """Same fingerprint with `bits` bits changed."""
    width = len(value) * 4
    mask = (1 << bits) - 1
    return f"{int(value, 16) ^ mask:0{len(value)}x}"


BASE_64 = "c3a90f7e21b45d80"
BASE_256 = "4f1c" * 16


class TestFingerprint(unittest.TestCase):
    def test_valid_fingerprints(self):
        Fingerprint(PHASH, BASE_64)
        Fingerprint(DHASH, BASE_64)
        Fingerprint(PDQ, BASE_256)

    def test_wrong_width_is_rejected(self):
        for kind, value in ((PHASH, BASE_256), (PDQ, BASE_64), (PHASH, "abc")):
            with self.subTest(kind=kind, width=len(value)):
                with self.assertRaises(FingerprintError):
                    Fingerprint(kind, value)

    def test_non_hex_is_rejected(self):
        for bad in ("C3A90F7E21B45D80", "zzzzzzzzzzzzzzzz", "", "0x c3a90f7e21b45d"):
            with self.subTest(value=bad):
                with self.assertRaises(FingerprintError):
                    Fingerprint(PHASH, bad)

    def test_distance_counts_differing_bits(self):
        self.assertEqual(phash(BASE_64).distance_to(phash(BASE_64)), 0)
        for bits in (1, 3, 8, 17):
            with self.subTest(bits=bits):
                self.assertEqual(
                    phash(BASE_64).distance_to(phash(flip(BASE_64, bits))), bits
                )

    def test_comparing_different_algorithms_is_refused(self):
        # A phash and a dhash of the same image are unrelated numbers; a
        # distance between them would be meaningless and look meaningful.
        with self.assertRaises(FingerprintError):
            Fingerprint(PHASH, BASE_64).distance_to(Fingerprint(DHASH, BASE_64))

    def test_normalisation_makes_widths_comparable(self):
        self.assertEqual(normalised_distance(8, 64), normalised_distance(32, 256))

    def test_quality_bounds(self):
        validate_quality(0)
        validate_quality(100)
        for bad in (-1, 101, 1.5, True, "80"):
            with self.subTest(quality=bad):
                with self.assertRaises(FingerprintError):
                    validate_quality(bad)


class TestClassification(unittest.TestCase):
    def test_two_close_algorithms_make_a_strong_candidate(self):
        band, capped = classify({PHASH: 4, DHASH: 5}, quality=90)
        self.assertEqual(band, Band.STRONG_CANDIDATE)
        self.assertFalse(capped)

    def test_one_close_algorithm_is_only_possible(self):
        # One hash agreeing is ordinary; agreement across independent
        # algorithms is what separates a candidate from a coincidence.
        band, _ = classify({PHASH: 4, DHASH: 30}, quality=90)
        self.assertEqual(band, Band.POSSIBLE)

    def test_two_loosely_close_algorithms_are_possible(self):
        band, _ = classify({PHASH: 12, DHASH: 13}, quality=90)
        self.assertEqual(band, Band.POSSIBLE)

    def test_one_loosely_close_algorithm_is_weak(self):
        band, _ = classify({PHASH: 14, DHASH: 40}, quality=90)
        self.assertEqual(band, Band.WEAK)

    def test_nothing_close_is_not_shown_at_all(self):
        band, _ = classify({PHASH: 40, DHASH: 44}, quality=90)
        self.assertIsNone(band)

    def test_low_quality_caps_the_band_and_says_so(self):
        # The wireframe's second alert: a closer distance and a weaker rating,
        # because low-detail images collide by coincidence far more often.
        strong = classify({PHASH: 3, DHASH: 4}, quality=90)
        capped = classify({PHASH: 3, DHASH: 4}, quality=LOW_QUALITY_CEILING - 1)
        self.assertEqual(strong[0], Band.STRONG_CANDIDATE)
        self.assertEqual(capped[0], Band.WEAK)
        self.assertTrue(capped[1])

    def test_quality_at_the_ceiling_is_not_capped(self):
        band, capped = classify({PHASH: 3, DHASH: 4}, quality=LOW_QUALITY_CEILING)
        self.assertEqual(band, Band.STRONG_CANDIDATE)
        self.assertFalse(capped)

    def test_capping_never_promotes(self):
        band, capped = classify({PHASH: 14, DHASH: 60}, quality=1)
        self.assertEqual(band, Band.WEAK)
        self.assertFalse(capped)

    def test_empty_distances_yield_nothing(self):
        self.assertEqual(classify({}, quality=90), (None, False))

    def test_widths_are_normalised_not_compared_raw(self):
        # 20 bits out of 256 is close; 20 out of 64 is not.
        self.assertEqual(classify({PDQ: 20}, quality=90)[0], Band.POSSIBLE)
        self.assertIsNone(classify({PHASH: 20}, quality=90)[0])


class IndexTestCase(unittest.TestCase):
    def setUp(self):
        self.index = NearMatchIndex()
        self.addCleanup(self.index.close)

    def add(self, position, base=BASE_64, bits=0, quality=90):
        self.index.add(
            position,
            [
                Fingerprint(PHASH, flip(base, bits)),
                Fingerprint(DHASH, flip(base, bits)),
            ],
            quality,
        )


class TestIndex(IndexTestCase):
    def test_add_and_count(self):
        for i in range(5):
            self.add(i, bits=i)
        self.assertEqual(self.index.size(), 5)

    def test_a_work_with_no_fingerprints_is_refused(self):
        # Silently indexing an unsearchable work would make it look covered.
        with self.assertRaises(NearMatchError):
            self.index.add(0, [], 90)

    def test_negative_position_is_refused(self):
        with self.assertRaises(NearMatchError):
            self.index.add(-1, [phash(BASE_64)], 90)

    def test_invalid_quality_is_refused(self):
        with self.assertRaises(FingerprintError):
            self.index.add(0, [phash(BASE_64)], 900)

    def test_an_exact_duplicate_is_the_strongest_candidate(self):
        self.add(0)
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)], 90
        )
        self.assertEqual(found[0].position, 0)
        self.assertEqual(found[0].band, Band.STRONG_CANDIDATE)
        self.assertEqual(found[0].distances[PHASH], 0)

    def test_unrelated_work_is_not_returned(self):
        self.add(0, base="0000000000000000")
        found = self.index.search([Fingerprint(PHASH, "ffffffffffffffff")], 90)
        self.assertEqual(found, [])

    def test_results_are_ranked_by_band_then_closeness(self):
        self.add(0, bits=20)   # far
        self.add(1, bits=2)    # near
        self.add(2, bits=13)   # middling
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)], 90
        )
        self.assertEqual([c.position for c in found][:2], [1, 2])

    def test_band_outranks_position(self):
        # The earlier test's far entry fell outside the threshold entirely, so
        # band order and position order happened to agree. Here they conflict:
        # a weak candidate registered first must not outrank a strong one.
        self.index.add(
            1,
            [Fingerprint(PHASH, flip(BASE_64, 14)), Fingerprint(DHASH, flip(BASE_64, 40))],
            90,
        )
        self.index.add(
            9,
            [Fingerprint(PHASH, flip(BASE_64, 2)), Fingerprint(DHASH, flip(BASE_64, 2))],
            90,
        )
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)], 90
        )
        self.assertEqual([c.band for c in found], [Band.STRONG_CANDIDATE, Band.WEAK])
        self.assertEqual([c.position for c in found], [9, 1])

    def test_exclusions_keep_an_artists_own_work_out(self):
        self.add(0)
        self.add(1)
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)], 90, exclude={0}
        )
        self.assertEqual([c.position for c in found], [1])

    def test_limit_is_honoured(self):
        for i in range(10):
            self.add(i, bits=i % 3)
        found = self.index.search([Fingerprint(PHASH, BASE_64)], 90, limit=3)
        self.assertEqual(len(found), 3)

    def test_invalid_search_arguments_are_refused(self):
        with self.assertRaises(NearMatchError):
            self.index.search([], 90)
        with self.assertRaises(NearMatchError):
            self.index.search([phash(BASE_64)], 90, limit=0)

    def test_only_shared_algorithms_are_compared(self):
        # An old record with fewer fingerprints must still be searchable on
        # whatever it does have, which is the whole reason for capturing
        # several: a later algorithm cannot be applied to it retroactively.
        self.index.add(0, [Fingerprint(PHASH, BASE_64)], 90)
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(PDQ, BASE_256)], 90
        )
        self.assertEqual(found[0].position, 0)
        self.assertEqual(set(found[0].distances), {PHASH})

    def test_the_lower_quality_of_the_pair_governs(self):
        # Comparing a detailed work against a flat one is only as reliable as
        # the flat one.
        self.add(0, quality=10)
        found = self.index.search(
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)], 95
        )
        self.assertEqual(found[0].band, Band.WEAK)
        self.assertTrue(found[0].quality_capped)

    def test_the_band_vocabulary_is_frozen_and_concludes_nothing(self):
        # The previous version of this test was decorative: .replace("near","")
        # was a no-op on every band value, and hasattr on a slots=True
        # dataclass is always False. Pin the vocabulary instead.
        self.assertEqual(
            {str(b) for b in Band}, {"strong_candidate", "possible", "weak"}
        )
        for band in Band:
            with self.subTest(band=band):
                self.assertNotIn("match", str(band))
                self.assertNotIn("confirmed", str(band))
                self.assertNotIn("verified", str(band))

    def test_quality_is_order_independent_across_incremental_adds(self):
        # Last-row-wins made the safety cap depend on SQLite row order, so the
        # same index content gave opposite verdicts.
        low_first = NearMatchIndex()
        self.addCleanup(low_first.close)
        low_first.add(1, [Fingerprint(DHASH, BASE_64)], 5)
        low_first.add(1, [Fingerprint(PHASH, BASE_64)], 90)
        high_first = NearMatchIndex()
        self.addCleanup(high_first.close)
        high_first.add(2, [Fingerprint(PHASH, BASE_64)], 90)
        high_first.add(2, [Fingerprint(DHASH, BASE_64)], 5)
        query = [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)]
        self.assertEqual(
            low_first.search(query, 90)[0].band, high_first.search(query, 90)[0].band
        )
        self.assertEqual(low_first.search(query, 90)[0].band, Band.WEAK)

    def test_duplicate_query_algorithms_are_refused(self):
        # Silently keeping the last would miss a match on the first.
        with self.assertRaises(NearMatchError):
            self.index.search(
                [Fingerprint(PHASH, BASE_64), Fingerprint(PHASH, flip(BASE_64, 3))], 90
            )

    def test_one_drifted_row_does_not_take_down_every_search(self):
        # The index is rebuildable and is never evidence, so skipping beats
        # failing closed on a partial rebuild.
        self.add(0)
        self.index._connection.execute(
            "INSERT OR REPLACE INTO fingerprints VALUES (7, 'phash', 'deadbeef', 90)"
        )
        found = self.index.search([Fingerprint(PHASH, BASE_64)], 90)
        self.assertTrue(any(c.position == 0 for c in found))
        self.assertEqual(self.index.unreadable_rows, 1)


class TestMonitoring(IndexTestCase):
    def test_only_earlier_registrations_are_alerted(self):
        # A later registration cannot be what was copied from.
        self.add(5)
        self.add(20)
        found = monitor(
            self.index,
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)],
            90,
            new_position=10,
        )
        self.assertEqual([c.position for c in found], [5])

    def test_later_near_matches_cannot_bury_an_earlier_registrant(self):
        # The attack: flood positions after the new registration with closer
        # matches. They are ineligible to alert, but truncating before
        # filtering let them consume the whole result budget and silently drop
        # the victim the alert exists for.
        self.index.add(
            0,
            [Fingerprint(PHASH, flip(BASE_64, 5)), Fingerprint(DHASH, flip(BASE_64, 5))],
            90,
        )
        for position in range(11, 411):
            self.index.add(
                position,
                [Fingerprint(PHASH, flip(BASE_64, 2)), Fingerprint(DHASH, flip(BASE_64, 2))],
                90,
            )
        alerts = monitor(
            self.index,
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)],
            90,
            new_position=10,
        )
        self.assertTrue(any(c.position == 0 for c in alerts))
        self.assertFalse(any(c.position >= 10 for c in alerts))

    def test_the_new_registration_does_not_alert_itself(self):
        self.add(7)
        found = monitor(
            self.index,
            [Fingerprint(PHASH, BASE_64), Fingerprint(DHASH, BASE_64)],
            90,
            new_position=7,
        )
        self.assertEqual(found, [])


class TestAlertPolicy(unittest.TestCase):
    def candidate(self, band):
        from certifiles.nearmatch import Candidate

        return Candidate(position=1, band=band, quality=90, distances={PHASH: 2})

    def test_weak_candidates_do_not_alert_by_default(self):
        policy = AlertPolicy()
        self.assertFalse(policy.admits(self.candidate(Band.WEAK), 0))
        self.assertTrue(policy.admits(self.candidate(Band.POSSIBLE), 0))
        self.assertTrue(policy.admits(self.candidate(Band.STRONG_CANDIDATE), 0))

    def test_the_daily_cap_holds(self):
        # Anyone can trigger alerts to a chosen artist by registering
        # near-matches, so an uncapped channel is a harassment vector aimed at
        # the people the product protects.
        policy = AlertPolicy(max_alerts_per_recipient_per_day=3)
        self.assertTrue(policy.admits(self.candidate(Band.STRONG_CANDIDATE), 2))
        self.assertFalse(policy.admits(self.candidate(Band.STRONG_CANDIDATE), 3))
        self.assertFalse(policy.admits(self.candidate(Band.STRONG_CANDIDATE), 99))

    def test_a_stricter_minimum_band_can_be_set(self):
        policy = AlertPolicy(minimum_band=Band.STRONG_CANDIDATE)
        self.assertFalse(policy.admits(self.candidate(Band.POSSIBLE), 0))


class TestThresholdsAreProvisional(unittest.TestCase):
    def test_the_module_says_the_thresholds_are_not_measured(self):
        # An accuracy claim built on unmeasured thresholds is unfounded, and
        # the interface shows a confidence band to artists. If this assertion
        # is ever removed, the eval harness had better exist.
        import re

        import certifiles.nearmatch as module

        prose = re.sub(r"\s+", " ", module.__doc__.lower())
        self.assertIn("provisional", prose)
        self.assertIn("eval harness", prose)
        self.assertIn("never returns a verdict", prose)


if __name__ == "__main__":
    unittest.main()
