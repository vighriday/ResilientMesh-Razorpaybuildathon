"""Tests for the ResilientMesh recovery benchmark.

The properties worth testing here are not "does it run". They are the four
claims a reviewer would otherwise have to take on faith: that the run is
reproducible, that the money arithmetic is exact integer paisa, that the
confidence interval is genuinely paired, and that each policy compliance
profile is the one the harness says it is.

Run with:  python eval/test_benchmark.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark  # noqa: E402
import generator  # noqa: E402
import policies  # noqa: E402
from generator import Attempt, afa_ceiling_paisa, build_observation, retention_bp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DOMAIN_MODELS_GO = REPO_ROOT / "internal" / "domain" / "models.go"
DOMAIN_RECORDS_GO = REPO_ROOT / "internal" / "domain" / "records.go"

# Small corpora keep the suite fast; the properties under test do not depend on
# corpus size, and the reproducibility test that does is run at full width.
SMALL_N = 120
SMALL_RESAMPLES = 500


def _load_costs() -> dict[str, int]:
    return benchmark.load_costs()


def _go_map_keys(source: str, declaration: str) -> set[str]:
    """Extract the quoted keys of a Go map literal.

    Brace matching starts after the declaration line rather than at the first
    brace, because `map[string]struct{}{` puts a balanced pair of braces on the
    declaration line itself.
    """
    start = source.index(declaration)
    line_end = source.index("\n", start) + 1
    depth = 1
    cursor = line_end
    while depth > 0:
        char = source[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        cursor += 1
    body = source[line_end:cursor - 1]
    return set(re.findall(r'^\s*"([^"]+)"\s*:', body, re.MULTILINE))


class TestReproducibility(unittest.TestCase):
    def test_same_seed_gives_identical_nrcv_and_manifest_hash(self) -> None:
        first = benchmark.run(SMALL_N, 20260904, resamples=SMALL_RESAMPLES,
                              permutations=SMALL_RESAMPLES, commit="")
        second = benchmark.run(SMALL_N, 20260904, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")

        self.assertEqual(
            [(p["name"], p["nrcv_paisa"]) for p in first["policies"]],
            [(p["name"], p["nrcv_paisa"]) for p in second["policies"]],
        )
        self.assertEqual(first["manifest"]["hash"], second["manifest"]["hash"])
        # Nothing in the report reads a clock, so the whole artifact is stable,
        # not merely the fields we happened to compare.
        self.assertEqual(json.dumps(first), json.dumps(second))

    def test_different_seed_changes_corpus_and_hash(self) -> None:
        first = benchmark.run(SMALL_N, 20260904, resamples=SMALL_RESAMPLES,
                              permutations=SMALL_RESAMPLES, commit="")
        other = benchmark.run(SMALL_N, 20260905, resamples=SMALL_RESAMPLES,
                              permutations=SMALL_RESAMPLES, commit="")
        self.assertNotEqual(first["manifest"]["hash"], other["manifest"]["hash"])
        self.assertNotEqual(
            first["manifest"]["attested"]["incidents_digest"],
            other["manifest"]["attested"]["incidents_digest"],
        )

    def test_generator_is_deterministic(self) -> None:
        self.assertEqual(
            generator.incidents_digest(generator.generate(60, 11)),
            generator.incidents_digest(generator.generate(60, 11)),
        )
        self.assertNotEqual(
            generator.incidents_digest(generator.generate(60, 11)),
            generator.incidents_digest(generator.generate(60, 12)),
        )

    def test_manifest_hash_rederives_from_published_attestation(self) -> None:
        """A verifier must be able to recheck the hash without re-running us."""
        import hashlib

        report = benchmark.run(SMALL_N, 7, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")
        manifest = report["manifest"]
        canonical = generator.canonical_json(manifest["attested"])
        self.assertEqual(hashlib.sha256(canonical.encode("utf-8")).hexdigest(), manifest["hash"])
        # The canonical bytes must be ASCII and free of the characters Go
        # escapes by default, or the Go verifier will disagree with us.
        self.assertTrue(canonical.isascii())
        for forbidden in ("<", ">", "&"):
            self.assertNotIn(forbidden, canonical)

    def test_generator_rejects_out_of_range_input(self) -> None:
        with self.assertRaises(ValueError):
            generator.generate(0, 1)
        with self.assertRaises(ValueError):
            generator.generate(generator.MAX_INCIDENTS + 1, 1)
        with self.assertRaises(ValueError):
            generator.generate(10, -1)
        with self.assertRaises(TypeError):
            generator.generate(10, "seed")  # type: ignore[arg-type]


class TestMoneyMath(unittest.TestCase):
    def setUp(self) -> None:
        self.costs = _load_costs()
        self.incidents = generator.generate(SMALL_N, 4242)

    def test_per_incident_nrcv_is_exact_integer_paisa(self) -> None:
        for name, planner in policies.POLICIES:
            for incident in self.incidents:
                outcome = policies.simulate(incident, planner, self.costs)
                for value in (outcome.recovered_paisa, outcome.nrcv_paisa, outcome.retries,
                              outcome.comms_messages, outcome.morphs, outcome.violations):
                    self.assertIsInstance(value, int, f"{name} produced a non-int")
                expected = (
                    outcome.recovered_paisa
                    - outcome.retries * self.costs["gateway_fee_per_attempt_paisa"]
                    - outcome.comms_messages * self.costs["comms_cost_per_message_paisa"]
                    - outcome.violations * self.costs["compliance_penalty_paisa"]
                    - outcome.morphs * self.costs["session_friction_paisa"]
                )
                self.assertEqual(outcome.nrcv_paisa, expected)

    def test_report_money_fields_are_integers(self) -> None:
        report = benchmark.run(SMALL_N, 4242, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")
        # mean_delta_paisa is a bootstrap statistic, not an accounting figure;
        # every other paisa field is money and must be exact.
        statistic_fields = {"mean_delta_paisa"}
        offenders: list[str] = []

        def walk(node: object, path: str) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    walk(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}[{index}]")
            elif path.split(".")[-1].endswith("_paisa"):
                if path.split(".")[-1] in statistic_fields:
                    return
                if isinstance(node, bool) or not isinstance(node, int):
                    offenders.append(f"{path} = {node!r}")

        walk(report, "report")
        self.assertEqual(offenders, [], f"non-integer money fields: {offenders}")

    def test_aggregate_matches_sum_of_per_incident_values(self) -> None:
        report = benchmark.run(SMALL_N, 4242, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")
        by_name = {entry["name"]: entry for entry in report["policies"]}
        for name, planner in policies.POLICIES:
            outcomes = [policies.simulate(i, planner, self.costs) for i in self.incidents]
            self.assertEqual(by_name[name]["nrcv_paisa"], sum(o.nrcv_paisa for o in outcomes))
            self.assertEqual(by_name[name]["retries"], sum(o.retries for o in outcomes))
            self.assertEqual(by_name[name]["violations"], sum(o.violations for o in outcomes))
            self.assertEqual(
                by_name[name]["gross_recovered_paisa"], sum(o.recovered_paisa for o in outcomes)
            )

    def test_delta_decomposition_is_exact(self) -> None:
        report = benchmark.run(SMALL_N, 4242, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")
        comparison = report["comparison"]
        self.assertEqual(
            sum(comparison["delta_components_paisa"].values()), comparison["delta_paisa"]
        )
        self.assertEqual(
            comparison["delta_paisa"],
            comparison["treatment_nrcv_paisa"] - comparison["baseline_nrcv_paisa"],
        )

    def test_indian_digit_grouping_and_ascii_rendering(self) -> None:
        self.assertEqual(benchmark.format_paisa(0), "INR 0.00")
        self.assertEqual(benchmark.format_paisa(1), "INR 0.01")
        self.assertEqual(benchmark.format_paisa(123_456_789), "INR 12,34,567.89")
        self.assertEqual(benchmark.format_paisa(-123_456_789), "-INR 12,34,567.89")
        self.assertEqual(benchmark.format_paisa(100_000), "INR 1,000.00")
        self.assertEqual(benchmark.format_signed_paisa(500), "+INR 5.00")
        self.assertEqual(benchmark.group_indian(10_000_000), "1,00,00,000")
        # Rendered output goes to a Windows console and a markdown file; a rupee
        # sign there is a UnicodeEncodeError on a redirected stdout.
        report = benchmark.run(40, 3, resamples=200, permutations=200, commit="")
        self.assertTrue(benchmark.render_markdown(report).isascii())


class TestCostModel(unittest.TestCase):
    def test_costs_json_matches_go_default_cost_model(self) -> None:
        """The shared file is the point; drift from the Go default defeats it."""
        source = DOMAIN_RECORDS_GO.read_text(encoding="utf-8")
        expected = {}
        for go_field, json_key in (
            ("GatewayFeePerAttemptPaisa", "gateway_fee_per_attempt_paisa"),
            ("CommsCostPerMessagePaisa", "comms_cost_per_message_paisa"),
            ("CompliancePenaltyPaisa", "compliance_penalty_paisa"),
            ("SessionFrictionPaisa", "session_friction_paisa"),
        ):
            match = re.search(rf"{go_field}:\s*(\d+),", source)
            self.assertIsNotNone(match, f"could not find {go_field} in models.go")
            expected[json_key] = int(match.group(1))
        self.assertEqual(_load_costs(), expected)

    def test_loader_rejects_malformed_cost_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "costs.json"

            path.write_text(json.dumps({"gateway_fee_per_attempt_paisa": 250}), encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_costs(path)

            full = {key: 100 for key in benchmark.COST_KEYS}
            # A float cost is the first step towards float money arithmetic.
            float_costs = dict(full, gateway_fee_per_attempt_paisa=2.5)
            path.write_text(json.dumps(float_costs), encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_costs(path)

            path.write_text(json.dumps(dict(full, comms_cost_per_message_paisa=-1)), encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_costs(path)

            path.write_text("not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_costs(path)

            path.write_text(json.dumps(full) + " " * (benchmark.MAX_COST_FILE_BYTES + 1), encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_costs(path)


class TestPairedStatistics(unittest.TestCase):
    def test_ci_is_computed_on_paired_differences_not_independent_samples(self) -> None:
        """A constant offset has zero paired variance and large unpaired variance.

        If the interval were built by resampling each policy independently it
        would inherit the between-incident spread of the amounts, which here is
        four orders of magnitude wider than the effect. The paired interval
        collapses onto the offset exactly.
        """
        rng = np.random.default_rng(0)
        baseline = rng.integers(0, 10_000_000, size=400).astype(np.int64)
        offset = 12_345
        treatment = baseline + offset

        low, high = benchmark.paired_bootstrap_ci(treatment - baseline, 2_000, seed=5)
        self.assertAlmostEqual(low, float(offset), places=6)
        self.assertAlmostEqual(high, float(offset), places=6)

        # The same data, resampled independently, must be visibly wider.
        unpaired_rng = np.random.default_rng(5)
        n = baseline.size
        draws = np.empty(2_000, dtype=np.float64)
        for index in range(2_000):
            a = baseline[unpaired_rng.integers(0, n, size=n)].mean()
            b = treatment[unpaired_rng.integers(0, n, size=n)].mean()
            draws[index] = b - a
        u_low, u_high = np.percentile(draws, [2.5, 97.5])
        self.assertGreater(u_high - u_low, 1000.0 * (high - low + 1.0))

    def test_reported_ci_uses_index_aligned_pairs(self) -> None:
        """The differences behind the interval must be per-incident, in order."""
        costs = _load_costs()
        incidents = generator.generate(SMALL_N, 909)
        report = benchmark.run(SMALL_N, 909, resamples=SMALL_RESAMPLES,
                               permutations=SMALL_RESAMPLES, commit="")
        comparison = report["comparison"]
        planners = dict(policies.POLICIES)

        treatment = [policies.simulate(i, planners[comparison["treatment"]], costs).nrcv_paisa
                     for i in incidents]
        baseline = [policies.simulate(i, planners[comparison["baseline"]], costs).nrcv_paisa
                    for i in incidents]
        pairwise = [t - b for t, b in zip(treatment, baseline)]

        self.assertEqual(comparison["n_pairs"], len(incidents))
        self.assertEqual(comparison["delta_paisa"], sum(pairwise))
        self.assertEqual(comparison["incidents_improved"], sum(1 for d in pairwise if d > 0))
        self.assertEqual(comparison["incidents_worsened"], sum(1 for d in pairwise if d < 0))

    def test_permutation_p_value_bounds(self) -> None:
        identical = np.zeros(200, dtype=np.int64)
        self.assertEqual(benchmark.paired_permutation_p(identical, 1_000, seed=1), 1.0)

        separated = np.full(200, 5_000, dtype=np.int64)
        p_value = benchmark.paired_permutation_p(separated, 1_000, seed=1)
        self.assertGreater(p_value, 0.0)
        self.assertLess(p_value, 0.01)

        rng = np.random.default_rng(3)
        noise = rng.integers(-1_000, 1_000, size=400).astype(np.int64)
        p_noise = benchmark.paired_permutation_p(noise, 1_000, seed=1)
        self.assertGreater(p_noise, 0.05)

    def test_statistics_reject_empty_input(self) -> None:
        empty = np.zeros(0, dtype=np.int64)
        with self.assertRaises(ValueError):
            benchmark.paired_bootstrap_ci(empty, 100, seed=1)
        with self.assertRaises(ValueError):
            benchmark.paired_permutation_p(empty, 100, seed=1)


class TestPolicyBehaviour(unittest.TestCase):
    def setUp(self) -> None:
        self.costs = _load_costs()
        self.incidents = generator.generate(400, 20260904)
        self.outcomes = {
            name: [policies.simulate(i, planner, self.costs) for i in self.incidents]
            for name, planner in policies.POLICIES
        }

    def _violations(self, name: str) -> int:
        return sum(o.violations for o in self.outcomes[name])

    def test_violation_profile_is_as_designed(self) -> None:
        recurring = sum(1 for i in self.incidents if i["is_recurring"])
        self.assertGreater(recurring, 0, "corpus must contain recurring mandates to test compliance")

        # A blind loop breaches the cooling window and the notice obligation on
        # every recurring attempt it makes.
        self.assertGreater(self._violations("blind_retry"), 0)
        # A rules table encodes the cooling window but has no notification path
        # and no ceiling check.
        self.assertGreater(self._violations("static_rules"), 0)
        # The incumbent has no India-specific compliance model at all.
        self.assertGreater(self._violations("incumbent_smart_retry"), 0)
        # The mesh has one, and it is not advisory.
        self.assertEqual(self._violations("resilientmesh"), 0)

        self.assertGreater(self._violations("blind_retry"), self._violations("static_rules"))

    def test_mesh_never_breaches_an_rbi_invariant_structurally(self) -> None:
        """Assert on the plan, not just on the referee count.

        The referee could in principle be wrong in the same direction as the
        policy. Checking the emitted attempts against the invariants directly
        removes that shared-mode failure.
        """
        for incident, outcome in zip(self.incidents, self.outcomes["resilientmesh"]):
            observation = build_observation(incident)
            self.assertLessEqual(len(outcome.attempts), policies.GLOBAL_MAX_ATTEMPTS)
            if outcome.attempts:
                self.assertNotIn(
                    observation["error_code"], generator.TERMINAL_DECLINE_CODES,
                    "mesh spent a gateway fee on a terminal decline",
                )

            if not observation["is_recurring"]:
                continue

            ceiling = afa_ceiling_paisa(observation["mandate_category"])
            previous = observation["arrival_ts"]
            for attempt in outcome.attempts:
                self.assertGreaterEqual(
                    attempt.at - previous, policies.MANDATE_COOLING_SECONDS,
                    "recurring re-debit inside the RBI cooling window",
                )
                self.assertTrue(attempt.pre_debit_notified, "recurring debit without a pre-debit notice")
                self.assertLessEqual(
                    observation["amount_paisa"], ceiling,
                    "recurring debit above the applicable AFA ceiling",
                )
                previous = attempt.at
            self.assertLessEqual(
                observation["attempts_in_cycle_before"] + len(outcome.attempts),
                policies.MANDATE_CYCLE_CAP,
            )

    def test_blind_retry_ignores_the_taxonomy_and_the_others_do_not(self) -> None:
        terminal = [i for i in self.incidents if i["error_code"] in generator.TERMINAL_DECLINE_CODES]
        self.assertGreater(len(terminal), 0)
        for incident in terminal:
            self.assertEqual(len(policies.simulate(incident, policies.plan_blind_retry, self.costs).attempts), 3)
            for name in ("static_rules", "incumbent_smart_retry", "resilientmesh"):
                planner = dict(policies.POLICIES)[name]
                self.assertEqual(
                    len(policies.simulate(incident, planner, self.costs).attempts), 0,
                    f"{name} retried a terminal decline",
                )

    def test_static_rules_treats_refreshable_declines_as_terminal(self) -> None:
        """The documented rules-engine weakness, and the mesh answer to it."""
        refreshable = [i for i in self.incidents
                       if i["error_code"] in generator.REFRESHABLE_DECLINE_CODES]
        self.assertGreater(len(refreshable), 0)
        for incident in refreshable:
            self.assertEqual(
                len(policies.simulate(incident, policies.plan_static_rules, self.costs).attempts), 0
            )
            mesh = policies.simulate(incident, policies.plan_resilientmesh, self.costs)
            self.assertGreater(len(mesh.attempts), 0)
            self.assertEqual(mesh.attempts[0].presentation, generator.P_NETWORK_TOKEN)

    def test_every_policy_stops(self) -> None:
        for name, outcomes in self.outcomes.items():
            for outcome in outcomes:
                self.assertLessEqual(len(outcome.attempts), policies.MAX_ATTEMPTS_HARD, name)

    def test_no_policy_can_read_the_latent_truth(self) -> None:
        observation = build_observation(self.incidents[0])
        self.assertNotIn("truth", observation)
        self.assertNotIn("draws", observation)
        self.assertEqual(set(observation), set(generator.OBSERVABLE_KEYS))

    def test_attempts_never_schedule_into_the_past(self) -> None:
        for name, planner in policies.POLICIES:
            for incident in self.incidents:
                # simulate raises if a planner emits a non-monotonic schedule.
                policies.simulate(incident, planner, self.costs)


class TestOutcomeModel(unittest.TestCase):
    def test_retention_decays_geometrically_and_stays_bounded(self) -> None:
        half_life = 3600
        self.assertEqual(retention_bp(0, half_life), 10_000)
        self.assertEqual(retention_bp(half_life, half_life), 5_000)
        self.assertEqual(retention_bp(2 * half_life, half_life), 2_500)
        self.assertEqual(retention_bp(10 ** 9, half_life), 0)
        previous = 10_001
        for elapsed in range(0, 8 * half_life, 137):
            value = retention_bp(elapsed, half_life)
            self.assertLessEqual(value, previous)
            self.assertGreaterEqual(value, 0)
            previous = value
        with self.assertRaises(ValueError):
            retention_bp(10, 0)

    def test_above_ceiling_mandate_debit_without_afa_is_declined(self) -> None:
        """The ceiling is enforced on the rail, not only by the regulator."""
        incidents = generator.generate(600, 555)
        above = [i for i in incidents
                 if i["is_recurring"]
                 and i["amount_paisa"] > afa_ceiling_paisa(i["mandate_category"])]
        self.assertGreater(len(above), 0, "corpus must exercise the AFA ceiling")
        for incident in above:
            attempt = Attempt(
                at=incident["arrival_ts"] + 86400,
                rail=incident["rail"],
                presentation=generator.P_UNCHANGED,
                in_session=False,
                pre_debit_notified=True,
                afa_obtained=False,
                comms_messages=1,
            )
            self.assertEqual(generator.success_probability_bp(incident, attempt), 0)

    def test_permanent_failures_never_recover(self) -> None:
        incidents = generator.generate(300, 77)
        permanent = [i for i in incidents if i["truth"]["class"] == generator.CLASS_PERMANENT]
        self.assertGreater(len(permanent), 0)
        for incident in permanent:
            for presentation in (generator.P_UNCHANGED, generator.P_NETWORK_TOKEN,
                                 generator.P_FRESH_AUTH):
                attempt = Attempt(
                    at=incident["arrival_ts"] + 5,
                    rail=incident["alt_rail"],
                    presentation=presentation,
                    in_session=True,
                    pre_debit_notified=True,
                    afa_obtained=True,
                    comms_messages=0,
                )
                self.assertEqual(generator.success_probability_bp(incident, attempt), 0)

    def test_outage_and_transient_share_the_ambiguous_code_pool(self) -> None:
        """If the error code alone separated the causes, the study would be rigged."""
        incidents = generator.generate(800, 31)
        outage_codes = {i["error_code"] for i in incidents
                        if i["truth"]["class"] == generator.CLASS_OUTAGE}
        transient_codes = {i["error_code"] for i in incidents
                           if i["truth"]["class"] == generator.CLASS_TRANSIENT}
        self.assertTrue(outage_codes & transient_codes)
        self.assertTrue(outage_codes <= generator.AMBIGUOUS_FAILURE_CODES)
        self.assertTrue(transient_codes <= generator.AMBIGUOUS_FAILURE_CODES)

    def test_common_random_numbers_are_shared_across_policies(self) -> None:
        """The same k-th attempt must resolve against the same draw for everyone."""
        incident = generator.generate(1, 5)[0]
        attempt = Attempt(
            at=incident["arrival_ts"],
            rail=incident["rail"],
            presentation=generator.P_UNCHANGED,
            in_session=False,
            pre_debit_notified=True,
            afa_obtained=True,
            comms_messages=0,
        )
        probability = generator.success_probability_bp(incident, attempt)
        for index, draw in enumerate(incident["draws"]):
            self.assertEqual(
                generator.attempt_success(incident, attempt, index), probability > draw
            )
        with self.assertRaises(IndexError):
            generator.attempt_success(incident, attempt, len(incident["draws"]))


class TestDomainTaxonomyMirror(unittest.TestCase):
    """The Python mirrors of the Go taxonomy are checked, not trusted."""

    def setUp(self) -> None:
        self.source = DOMAIN_MODELS_GO.read_text(encoding="utf-8")

    def test_terminal_codes_match(self) -> None:
        self.assertEqual(
            _go_map_keys(self.source, "var TerminalDeclineCodes = map[string]string{"),
            set(generator.TERMINAL_DECLINE_CODES),
        )

    def test_refreshable_codes_match(self) -> None:
        self.assertEqual(
            _go_map_keys(self.source, "var RefreshableDeclineCodes = map[string]string{"),
            set(generator.REFRESHABLE_DECLINE_CODES),
        )

    def test_ambiguous_codes_match(self) -> None:
        self.assertEqual(
            _go_map_keys(self.source, "var AmbiguousFailureCodes = map[string]struct{}{"),
            set(generator.AMBIGUOUS_FAILURE_CODES),
        )

    def test_soft_decline_codes_match(self) -> None:
        self.assertEqual(
            _go_map_keys(self.source, "var SoftDeclineCodes = map[string]struct{}{"),
            set(generator.SOFT_DECLINE_CODES),
        )

    def test_afa_ceilings_match(self) -> None:
        records = DOMAIN_RECORDS_GO.read_text(encoding="utf-8")
        general = re.search(r"AFACeilingGeneralPaisa\s+int64\s*=\s*([0-9_]+)", records)
        elevated = re.search(r"AFACeilingElevatedPaisa\s+int64\s*=\s*([0-9_]+)", records)
        self.assertIsNotNone(general)
        self.assertIsNotNone(elevated)
        self.assertEqual(afa_ceiling_paisa("general"), int(general.group(1).replace("_", "")))
        self.assertEqual(afa_ceiling_paisa("insurance"), int(elevated.group(1).replace("_", "")))
        self.assertEqual(afa_ceiling_paisa("mutual_fund"), afa_ceiling_paisa("insurance"))
        self.assertEqual(afa_ceiling_paisa("credit_card_bill"), afa_ceiling_paisa("insurance"))
        # An unknown category must never widen a regulatory limit.
        self.assertEqual(afa_ceiling_paisa("something_new"), afa_ceiling_paisa("general"))


class TestReportSchema(unittest.TestCase):
    """Field names the judge harness reads by name. Renaming one breaks it silently."""

    def setUp(self) -> None:
        self.report = benchmark.run(SMALL_N, 20260904, resamples=SMALL_RESAMPLES,
                                    permutations=SMALL_RESAMPLES, commit="")

    def test_policy_entries_carry_the_contract_fields(self) -> None:
        required = {
            "name", "gross_recovered_paisa", "gross_recovered_display", "retries",
            "violations", "nrcv_paisa", "nrcv_display", "recovery_rate",
        }
        self.assertEqual(
            [entry["name"] for entry in self.report["policies"]], list(policies.POLICY_NAMES)
        )
        self.assertEqual(len(self.report["policies"]), 4)
        for entry in self.report["policies"]:
            self.assertTrue(required <= set(entry), f"{entry['name']} is missing {required - set(entry)}")
            self.assertGreaterEqual(entry["recovery_rate"], 0.0)
            self.assertLessEqual(entry["recovery_rate"], 1.0)

    def test_comparison_and_manifest_carry_the_contract_fields(self) -> None:
        comparison = self.report["comparison"]
        self.assertTrue({"ci_display", "p_value", "baseline", "treatment", "paired",
                         "ci_low_paisa", "ci_high_paisa", "delta_paisa"} <= set(comparison))
        self.assertTrue(comparison["paired"])
        self.assertNotEqual(comparison["baseline"], comparison["treatment"])
        self.assertGreater(comparison["p_value"], 0.0)
        self.assertLessEqual(comparison["p_value"], 1.0)
        self.assertLessEqual(comparison["ci_low_paisa"], comparison["ci_high_paisa"])

        manifest = self.report["manifest"]
        self.assertTrue({"hash", "algorithm", "attested"} <= set(manifest))
        self.assertEqual(manifest["algorithm"], "sha256")
        self.assertRegex(manifest["hash"], r"^[0-9a-f]{64}$")
        self.assertTrue(
            {"seed", "incident_count", "incidents_digest", "cost_model", "policy_config",
             "generator_version", "git_commit"} <= set(manifest["attested"])
        )

    def test_strongest_baseline_is_chosen_by_measurement(self) -> None:
        by_name = {entry["name"]: entry for entry in self.report["policies"]}
        baselines = {name: by_name[name]["nrcv_paisa"]
                     for name in policies.POLICY_NAMES if name != policies.TREATMENT_POLICY}
        self.assertEqual(
            self.report["comparison"]["baseline"], max(baselines, key=lambda k: baselines[k])
        )


class TestCommandLine(unittest.TestCase):
    def test_help_exits_cleanly(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(REPO_ROOT / "eval" / "benchmark.py"), "--help"],
            capture_output=True, text=True, timeout=120, check=False, cwd=str(REPO_ROOT),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--incidents", completed.stdout)

    def test_end_to_end_run_writes_a_parseable_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "benchmark.json"
            completed = subprocess.run(
                [sys.executable, str(REPO_ROOT / "eval" / "benchmark.py"),
                 "--incidents", "60", "--seed", "13", "--out", str(out), "--quiet"],
                capture_output=True, text=True, timeout=600, check=False, cwd=str(REPO_ROOT),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "", "--quiet must not print the table")
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["incidents"], 60)
            self.assertEqual(report["seed"], 13)
            first_bytes = out.read_bytes()

            completed = subprocess.run(
                [sys.executable, str(REPO_ROOT / "eval" / "benchmark.py"),
                 "--incidents", "60", "--seed", "13", "--out", str(out), "--quiet"],
                capture_output=True, text=True, timeout=600, check=False, cwd=str(REPO_ROOT),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(out.read_bytes(), first_bytes, "artifact must be byte-reproducible")

    def test_rejects_invalid_arguments(self) -> None:
        parser = benchmark.build_parser()
        for argv in (["--incidents", "0"], ["--incidents", "x"], ["--seed", "-1"]):
            with self.assertRaises(SystemExit):
                parser.parse_args(argv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
