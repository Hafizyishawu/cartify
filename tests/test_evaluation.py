"""Eval harness tests.

These check the instrument, not the thresholds. Everything here runs on
modelled fingerprints, which is exactly what the harness refuses to accept as a
basis for recommending an operating point — a distinction several of these
tests exist to hold in place.
"""

import unittest

from certifiles.fingerprint import LOW_QUALITY_CEILING, Fingerprint, FingerprintKind
from certifiles.evaluation import (
    Counts,
    Dataset,
    EvaluationError,
    Pair,
    Provenance,
    Sample,
    compare,
    evaluate,
    recommend,
    sweep,
)
from certifiles.nearmatch import Band

PHASH = FingerprintKind.PHASH
DHASH = FingerprintKind.DHASH
BASE = "c3a90f7e21b45d80"


def flip(value: str, bits: int) -> str:
    return f"{int(value, 16) ^ ((1 << bits) - 1):0{len(value)}x}"


def sample(work_id: str, bits: int = 0, quality: int = 90) -> Sample:
    return Sample(
        work_id=work_id,
        fingerprints=(
            Fingerprint(PHASH, flip(BASE, bits)),
            Fingerprint(DHASH, flip(BASE, bits)),
        ),
        quality=quality,
    )


def pair(bits, same, transform, quality=90) -> Pair:
    return Pair(
        left=sample("original", 0, quality),
        right=sample("candidate", bits, quality),
        same_work=same,
        transform=transform,
    )


def dataset(pairs, provenance=Provenance.MODELLED) -> Dataset:
    return Dataset(pairs=pairs, provenance=provenance)


class TestCounts(unittest.TestCase):
    def test_metrics_from_a_confusion_matrix(self):
        counts = Counts(true_positive=8, false_positive=2, true_negative=90, false_negative=4)
        self.assertAlmostEqual(counts.precision, 0.8)
        self.assertAlmostEqual(counts.recall, 8 / 12)
        self.assertAlmostEqual(counts.false_positive_rate, 2 / 92)

    def test_undefined_metrics_are_none_not_zero(self):
        # Zero would read as "perfectly bad" when the truth is "no data".
        empty = Counts()
        self.assertIsNone(empty.precision)
        self.assertIsNone(empty.recall)
        self.assertIsNone(empty.false_positive_rate)

    def test_plus_accumulates_each_quadrant(self):
        counts = Counts().plus(True, True).plus(True, False).plus(False, True).plus(False, False)
        self.assertEqual(
            (counts.true_positive, counts.false_positive, counts.false_negative, counts.true_negative),
            (1, 1, 1, 1),
        )


class TestDataset(unittest.TestCase):
    def test_an_empty_dataset_is_refused(self):
        with self.assertRaises(EvaluationError):
            Dataset(pairs=[], provenance=Provenance.MEASURED)

    def test_round_trips_through_json(self):
        original = dataset([pair(2, True, "jpeg-q40"), pair(40, False, "unrelated")])
        restored = Dataset.from_json(original.to_json())
        self.assertEqual(restored.provenance, original.provenance)
        self.assertEqual(len(restored.pairs), 2)
        self.assertEqual(restored.pairs[0].distances(), original.pairs[0].distances())

    def test_pairs_sharing_no_algorithm_are_refused(self):
        # Silently scoring zero shared algorithms as "not similar" would count
        # a measurement failure as a true negative.
        left = Sample("a", (Fingerprint(PHASH, BASE),), 90)
        right = Sample("b", (Fingerprint(DHASH, BASE),), 90)
        with self.assertRaises(EvaluationError):
            Pair(left, right, True, "cross-algorithm").distances()

    def test_pair_quality_is_the_lower_of_the_two(self):
        self.assertEqual(
            Pair(sample("a", 0, 80), sample("b", 0, 20), True, "t").quality(), 20
        )

    def test_transforms_lists_only_positive_labels(self):
        data = dataset([pair(2, True, "crop-10"), pair(40, False, "unrelated")])
        self.assertEqual(data.transforms, ["crop-10"])


class TestEvaluate(unittest.TestCase):
    def test_a_perfect_separation_scores_perfectly(self):
        data = dataset([pair(1, True, "jpeg-q90"), pair(60, False, "unrelated")])
        report = evaluate(data)
        self.assertEqual(report.overall.precision, 1.0)
        self.assertEqual(report.overall.recall, 1.0)
        self.assertEqual(report.overall.false_positive_rate, 0.0)

    def test_a_near_negative_becomes_a_false_positive(self):
        data = dataset([pair(2, False, "same-artist")])
        report = evaluate(data)
        self.assertEqual(report.overall.false_positive, 1)
        self.assertEqual(report.overall.precision, 0.0)

    def test_a_distant_positive_becomes_a_false_negative(self):
        data = dataset([pair(40, True, "crop-50")])
        report = evaluate(data)
        self.assertEqual(report.overall.false_negative, 1)
        self.assertEqual(report.overall.recall, 0.0)

    def test_recall_is_broken_down_per_transform(self):
        # A single recall figure hides that one transform is failing entirely.
        data = dataset(
            [
                pair(1, True, "jpeg-q90"),
                pair(2, True, "jpeg-q90"),
                pair(45, True, "crop-40"),
                pair(50, True, "crop-40"),
            ]
        )
        report = evaluate(data)
        self.assertEqual(report.per_transform["jpeg-q90"].recall, 1.0)
        self.assertEqual(report.per_transform["crop-40"].recall, 0.0)

    def test_precision_is_stratified_by_quality(self):
        # The central design claim is that low-detail images behave
        # differently. Without this breakdown the harness cannot check it.
        data = dataset(
            [
                pair(2, False, "unrelated", quality=90),
                pair(2, False, "unrelated", quality=LOW_QUALITY_CEILING - 5),
            ]
        )
        report = evaluate(data)
        self.assertIn("low detail", report.per_quality)
        self.assertIn("sufficient detail", report.per_quality)

    def test_the_operating_band_changes_what_counts_as_surfaced(self):
        # WEAK needs one algorithm close and the other not; flipping both
        # equally puts two inside the loose threshold, which is POSSIBLE.
        weak = Pair(
            left=sample("original"),
            right=Sample(
                "candidate",
                (
                    Fingerprint(PHASH, flip(BASE, 14)),
                    Fingerprint(DHASH, flip(BASE, 40)),
                ),
                90,
            ),
            same_work=True,
            transform="crop-15",
        )
        from certifiles.nearmatch import classify

        self.assertEqual(classify(weak.distances(), weak.quality())[0], Band.WEAK)
        data = dataset([weak])
        self.assertEqual(evaluate(data, operating_band=Band.POSSIBLE).overall.recall, 0.0)
        self.assertEqual(evaluate(data, operating_band=Band.WEAK).overall.recall, 1.0)

    def test_a_low_quality_positive_is_suppressed_by_the_cap(self):
        close_but_flat = pair(1, True, "jpeg-q90", quality=LOW_QUALITY_CEILING - 1)
        report = evaluate(dataset([close_but_flat]), operating_band=Band.POSSIBLE)
        self.assertEqual(report.overall.recall, 0.0)

    def test_render_marks_modelled_data_as_unusable_for_claims(self):
        report = evaluate(dataset([pair(1, True, "jpeg-q90")]))
        self.assertFalse(report.is_defensible)
        self.assertIn("NOT a basis", report.render())

    def test_render_does_not_warn_on_measured_data(self):
        data = dataset([pair(1, True, "jpeg-q90")], provenance=Provenance.MEASURED)
        report = evaluate(data)
        self.assertTrue(report.is_defensible)
        self.assertNotIn("NOT a basis", report.render())


class TestSweep(unittest.TestCase):
    def test_sweep_scores_every_valid_combination(self):
        data = dataset([pair(2, True, "jpeg-q90"), pair(40, False, "unrelated")])
        reports = sweep(data, tights=[0.05, 0.10], looses=[0.20, 0.30])
        self.assertEqual(len(reports), 4)

    def test_invalid_combinations_are_skipped_not_scored(self):
        data = dataset([pair(2, True, "jpeg-q90")])
        reports = sweep(data, tights=[0.30], looses=[0.10, 0.40])
        self.assertEqual(len(reports), 1)

    def test_a_sweep_with_no_valid_combination_is_refused(self):
        data = dataset([pair(2, True, "jpeg-q90")])
        with self.assertRaises(EvaluationError):
            sweep(data, tights=[0.5], looses=[0.1])

    def test_results_are_ordered_by_precision(self):
        data = dataset(
            [pair(2, True, "jpeg-q90"), pair(10, False, "same-artist")]
        )
        reports = sweep(data, tights=[0.02, 0.20], looses=[0.05, 0.40])
        precisions = [r.overall.precision or 0 for r in reports]
        self.assertEqual(precisions, sorted(precisions, reverse=True))


class TestRecommend(unittest.TestCase):
    def measured(self, pairs):
        return Dataset(pairs=pairs, provenance=Provenance.MEASURED)

    def test_modelled_data_cannot_produce_a_recommendation(self):
        # The whole point: building the harness closes nothing.
        data = dataset([pair(1, True, "jpeg-q90"), pair(60, False, "unrelated")])
        with self.assertRaises(EvaluationError) as caught:
            recommend(data, tights=[0.1], looses=[0.2])
        self.assertIn("modelled", str(caught.exception))

    def test_measured_data_yields_the_highest_recall_above_the_floor(self):
        # The two candidate points must differ in recall, or picking the best
        # and picking the worst are indistinguishable.
        data = self.measured(
            [
                pair(1, True, "jpeg-q90"),
                pair(20, True, "crop-25"),
                pair(60, False, "unrelated"),
            ]
        )
        narrow = evaluate(data, tight=0.05, loose=0.10)
        wide = evaluate(data, tight=0.05, loose=0.40)
        self.assertEqual((narrow.overall.recall, wide.overall.recall), (0.5, 1.0))
        self.assertEqual(narrow.overall.precision, 1.0)
        self.assertEqual(wide.overall.precision, 1.0)

        best = recommend(
            data, tights=[0.05], looses=[0.10, 0.40], minimum_precision=0.9
        )
        self.assertEqual(best.overall.recall, 1.0)
        self.assertEqual(best.loose, 0.40)

    def test_an_unreachable_precision_floor_is_refused_not_relaxed(self):
        # Widening the search to reach a floor would trade accusations for
        # coverage, which is the opposite of what precision is for.
        data = self.measured([pair(2, False, "same-artist"), pair(3, True, "jpeg-q90")])
        with self.assertRaises(EvaluationError) as caught:
            recommend(data, tights=[0.1], looses=[0.3], minimum_precision=0.99)
        self.assertIn("no threshold", str(caught.exception))


class TestRegressionComparison(unittest.TestCase):
    def build(self, pairs):
        return evaluate(dataset(pairs))

    def test_no_change_is_no_regression(self):
        pairs = [pair(1, True, "jpeg-q90"), pair(60, False, "unrelated")]
        self.assertEqual(compare(self.build(pairs), self.build(pairs)), [])

    def test_a_precision_drop_is_reported(self):
        baseline = self.build([pair(1, True, "jpeg-q90"), pair(60, False, "unrelated")])
        current = self.build([pair(1, True, "jpeg-q90"), pair(2, False, "same-artist")])
        found = compare(baseline, current)
        self.assertTrue(any(r.metric == "precision" for r in found))

    def test_a_silent_recall_drop_on_one_transform_is_caught(self):
        # The failure this exists for: overall numbers hold while one transform
        # collapses, and nothing else in the system would notice.
        baseline = self.build([pair(2, True, "crop-10"), pair(2, True, "jpeg-q90")])
        current = self.build([pair(45, True, "crop-10"), pair(2, True, "jpeg-q90")])
        found = compare(baseline, current)
        self.assertTrue(any("crop-10" in r.metric for r in found))

    def test_a_transform_disappearing_counts_as_a_regression(self):
        baseline = self.build([pair(2, True, "crop-10")])
        current = self.build([pair(2, True, "jpeg-q90")])
        self.assertTrue(any("crop-10" in r.metric for r in compare(baseline, current)))

    def test_small_movements_are_within_tolerance(self):
        baseline = self.build([pair(1, True, "t")] * 100)
        current = self.build([pair(1, True, "t")] * 99 + [pair(60, True, "t")])
        self.assertEqual(compare(baseline, current, tolerance=0.02), [])

    def test_an_improvement_is_never_a_regression(self):
        baseline = self.build([pair(45, True, "crop-10"), pair(60, False, "unrelated")])
        current = self.build([pair(2, True, "crop-10"), pair(60, False, "unrelated")])
        self.assertEqual(compare(baseline, current), [])

    def test_invalid_tolerance_is_refused(self):
        report = self.build([pair(1, True, "t")])
        for bad in (-0.1, 1.0, 2):
            with self.subTest(tolerance=bad):
                with self.assertRaises(EvaluationError):
                    compare(report, report, tolerance=bad)


class TestHarnessHonesty(unittest.TestCase):
    def test_the_module_says_building_it_closes_nothing(self):
        import re

        import certifiles.evaluation as module

        prose = re.sub(r"\s+", " ", module.__doc__)
        self.assertIn("Building this closes nothing", prose)

    def test_provenance_survives_a_round_trip(self):
        # If provenance were lost in serialisation, a modelled dataset could be
        # reloaded as measured and used to justify an operating point.
        data = dataset([pair(1, True, "t")], provenance=Provenance.MODELLED)
        self.assertEqual(
            Dataset.from_json(data.to_json()).provenance, Provenance.MODELLED
        )


if __name__ == "__main__":
    unittest.main()
