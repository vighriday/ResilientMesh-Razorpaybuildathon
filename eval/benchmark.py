"""ResilientMesh recovery benchmark: four policies, one incident corpus, one hash.

Runs blind retry, a static rules table, an incumbent-style smart retry, and
ResilientMesh over the identical seeded incidents and reports net recovered
contribution value in integer paisa. A point estimate is not evidence, so the
headline number is accompanied by a paired bootstrap 95% confidence interval and
a paired permutation test against the strongest baseline -- whichever policy that
turns out to be, chosen by measured NRCV rather than by us.

Every run emits an attestation manifest: SHA-256 over the canonical JSON of the
seed, the incident corpus digest, the cost model, the full policy configuration,
the generator version and the git commit. Nothing in the output depends on wall
clock time, so the same inputs produce a byte-identical artifact and the hash is
checkable by anyone who re-runs it.

Usage:
    python eval/benchmark.py --incidents 500 --seed 20260904 --out artifacts/benchmark.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

if __package__ in (None, ""):
    # Allow `python eval/benchmark.py` from any working directory as well as
    # `python -m unittest` discovery, without turning eval/ into a package.
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from generator import (  # noqa: E402
    GENERATOR_VERSION,
    canonical_json,
    generate,
    incidents_digest,
)
from policies import (  # noqa: E402
    POLICIES,
    POLICY_CONFIG,
    POLICY_NAMES,
    TREATMENT_POLICY,
    nrcv_paisa,
    simulate,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
COSTS_PATH = REPO_ROOT / "eval" / "costs.json"

# Bumped when the shape of artifacts/benchmark.json changes. Attested, so an
# older consumer can tell it is looking at a format it does not understand.
SCHEMA_VERSION = 1

DEFAULT_INCIDENTS = 500
DEFAULT_SEED = 20260904
DEFAULT_OUT = "artifacts/benchmark.json"

BOOTSTRAP_RESAMPLES = 10_000
PERMUTATIONS = 10_000
CI_ALPHA_BP = 500  # 95% interval
_RESAMPLE_CHUNK = 512  # bounds peak memory regardless of corpus size

COST_KEYS = (
    "gateway_fee_per_attempt_paisa",
    "comms_cost_per_message_paisa",
    "compliance_penalty_paisa",
    "session_friction_paisa",
)
MAX_COST_FILE_BYTES = 64 * 1024
MAX_COST_PAISA = 1_000_000_000_000


# ---------------------------------------------------------------------------
# Cost model
# ---------------------------------------------------------------------------


def load_costs(path: Path = COSTS_PATH) -> dict[str, int]:
    """Read the cost table Go also reads, and refuse anything ambiguous.

    Substituting a default for an unreadable file would defeat the entire point
    of the shared file: a reviewer has to be able to trust that the numbers in
    this report are the numbers the running system optimises. A missing or
    malformed table is therefore fatal rather than quietly patched.

    Floats are rejected outright. A cost model that arrives as 2.5 rupees
    instead of 250 paisa is the first step towards float money arithmetic, and
    the cheapest place to stop it is at the boundary.
    """
    raw = path.read_bytes()
    if len(raw) > MAX_COST_FILE_BYTES:
        raise ValueError(f"{path}: cost model is {len(raw)} bytes, over the {MAX_COST_FILE_BYTES} byte cap")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cost model is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{path}: cost model must be a JSON object")

    costs: dict[str, int] = {}
    for key in COST_KEYS:
        if key not in parsed:
            raise ValueError(f"{path}: cost model is missing {key}")
        value = parsed[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path}: {key} must be an integer number of paisa, got {value!r}")
        if value < 0 or value > MAX_COST_PAISA:
            raise ValueError(f"{path}: {key} = {value} is outside [0, {MAX_COST_PAISA}]")
        costs[key] = value
    return costs


# ---------------------------------------------------------------------------
# Display. Money is int paisa everywhere; rupees exist only in these two
# functions and only for humans.
# ---------------------------------------------------------------------------


def group_indian(value: int) -> str:
    """Group digits the Indian way: last three, then pairs (12,34,567)."""
    digits = str(value)
    if len(digits) <= 3:
        return digits
    head, tail = digits[:-3], digits[-3:]
    parts: list[str] = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return ",".join(parts) + "," + tail


def format_paisa(paisa: int) -> str:
    """Render integer paisa as an ASCII rupee string.

    Deliberately ASCII: this text is printed to a Windows console and embedded
    in a markdown report, and a rupee sign there is a UnicodeEncodeError waiting
    for a redirected stdout.
    """
    paisa = int(paisa)
    sign = "-" if paisa < 0 else ""
    rupees, remainder = divmod(abs(paisa), 100)
    return f"{sign}INR {group_indian(rupees)}.{remainder:02d}"


def format_signed_paisa(paisa: int) -> str:
    paisa = int(paisa)
    return ("+" if paisa >= 0 else "") + format_paisa(paisa)


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _bootstrap_means(diffs: np.ndarray, resamples: int, rng: np.random.Generator) -> np.ndarray:
    """Bootstrap the mean of the paired differences.

    Resampling *pairs* -- one index drawn per resample slot, used for both
    policies -- is what makes this a paired interval. Resampling each policy
    independently would inflate the width with between-incident variance that
    the paired design has already removed, and would answer a question nobody
    asked.
    """
    n = diffs.size
    means = np.empty(resamples, dtype=np.float64)
    done = 0
    while done < resamples:
        block = min(_RESAMPLE_CHUNK, resamples - done)
        index = rng.integers(0, n, size=(block, n))
        means[done:done + block] = diffs[index].mean(axis=1)
        done += block
    return means


def paired_bootstrap_ci(
    diffs: np.ndarray, resamples: int, seed: int, alpha_bp: int = CI_ALPHA_BP
) -> tuple[float, float]:
    """Percentile bootstrap interval on the mean paired difference."""
    if diffs.size == 0:
        raise ValueError("benchmark: cannot bootstrap an empty difference vector")
    rng = np.random.default_rng(seed)
    means = _bootstrap_means(diffs.astype(np.float64), resamples, rng)
    low_pct = alpha_bp / 200.0
    high_pct = 100.0 - low_pct
    low, high = np.percentile(means, [low_pct, high_pct])
    return float(low), float(high)


def paired_permutation_p(diffs: np.ndarray, permutations: int, seed: int) -> float:
    """Two-sided paired permutation (sign-flip) test on the mean difference.

    Under the null that the two policies are exchangeable within a pair, the
    sign of each paired difference is arbitrary. Flipping signs is therefore the
    exact permutation distribution for this design, and it needs no distributional
    assumption about NRCV -- which is heavily zero-inflated and nothing like normal.

    The +1 in numerator and denominator is the standard correction: with a finite
    number of permutations, a p-value of exactly zero is not a result the
    procedure can support.
    """
    if diffs.size == 0:
        raise ValueError("benchmark: cannot permute an empty difference vector")
    values = diffs.astype(np.float64)
    observed = abs(float(values.mean()))
    rng = np.random.default_rng(seed)
    n = values.size
    extreme = 0
    done = 0
    while done < permutations:
        block = min(_RESAMPLE_CHUNK, permutations - done)
        signs = rng.integers(0, 2, size=(block, n)) * 2 - 1
        means = (values * signs).mean(axis=1)
        # Tolerance because the permuted mean of an all-equal difference vector
        # must count as "at least as extreme" despite float rounding.
        extreme += int(np.count_nonzero(np.abs(means) >= observed - 1e-9))
        done += block
    return (extreme + 1) / (permutations + 1)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


def git_commit(root: Path = REPO_ROOT) -> str:
    """Best-effort code version for the manifest.

    Invoked without a shell and with the output validated as a 40-character hex
    string, so nothing an environment can put on the path turns into an
    injection. An unavailable git is not an error: the manifest simply attests
    an empty commit and says so.
    """
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    commit = completed.stdout.strip()
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else ""


def build_manifest(
    seed: int,
    incidents: list[dict[str, Any]],
    costs: dict[str, int],
    commit: str,
) -> dict[str, Any]:
    """Hash everything that could change the headline number.

    The attested object is published verbatim alongside its digest so that a
    verifier -- meshctl bench verify -- can re-canonicalise it and recompute the
    hash without re-running the benchmark. It contains only integers and ASCII
    strings: no floats, no non-ASCII, and none of the characters Go escapes by
    default, so the canonical bytes are identical in both languages.
    """
    attested: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "seed": int(seed),
        "incident_count": len(incidents),
        "incidents_digest": incidents_digest(incidents),
        "generator_version": GENERATOR_VERSION,
        "git_commit": commit,
        "cost_model": {key: int(costs[key]) for key in COST_KEYS},
        "policy_names": list(POLICY_NAMES),
        "policy_config": POLICY_CONFIG,
        "statistics": {
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "permutations": PERMUTATIONS,
            "ci_alpha_bp": CI_ALPHA_BP,
            "paired": 1,
        },
    }
    canonical = canonical_json(attested)
    return {
        "hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "algorithm": "sha256",
        "canonical_form": "json:sort_keys,separators=(',',':'),ensure_ascii,utf-8",
        "attested": attested,
    }


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def run(
    incident_count: int = DEFAULT_INCIDENTS,
    seed: int = DEFAULT_SEED,
    costs: dict[str, int] | None = None,
    resamples: int = BOOTSTRAP_RESAMPLES,
    permutations: int = PERMUTATIONS,
    commit: str | None = None,
) -> dict[str, Any]:
    """Execute the full benchmark and return the report structure."""
    if costs is None:
        costs = load_costs()
    if resamples < 1 or permutations < 1:
        raise ValueError("benchmark: resample and permutation counts must be positive")

    incidents = generate(incident_count, seed)

    # One row per (policy, incident). pandas does the aggregation; every value
    # in a money column is a Python int placed there by policies.simulate, and
    # sums over int64 stay exact for any corpus this harness will ever draw.
    rows: list[dict[str, Any]] = []
    for name, planner in POLICIES:
        for incident in incidents:
            outcome = simulate(incident, planner, costs)
            rows.append({
                "policy": name,
                "incident_id": incident["incident_id"],
                "recovered": int(outcome.recovered),
                "recovered_paisa": outcome.recovered_paisa,
                "retries": outcome.retries,
                "comms_messages": outcome.comms_messages,
                "morphs": outcome.morphs,
                "violations": outcome.violations,
                "nrcv_paisa": outcome.nrcv_paisa,
            })

    frame = pd.DataFrame(rows)
    # Sorting by incident id before pivoting makes the per-incident vectors
    # index-aligned across policies. Without it the pairing would depend on row
    # order, which is exactly the kind of silent coupling that turns a paired
    # test into a wrong one.
    frame = frame.sort_values(["policy", "incident_id"], kind="mergesort")

    per_policy: dict[str, np.ndarray] = {}
    policies_out: list[dict[str, Any]] = []
    for name in POLICY_NAMES:
        subset = frame[frame["policy"] == name]
        nrcv_vector = subset["nrcv_paisa"].to_numpy(dtype=np.int64)
        per_policy[name] = nrcv_vector

        recovered_count = int(subset["recovered"].sum())
        gross = int(subset["recovered_paisa"].sum())
        retries = int(subset["retries"].sum())
        comms = int(subset["comms_messages"].sum())
        morphs = int(subset["morphs"].sum())
        violations = int(subset["violations"].sum())
        total_nrcv = int(nrcv_vector.sum())

        gateway_cost = retries * costs["gateway_fee_per_attempt_paisa"]
        comms_cost = comms * costs["comms_cost_per_message_paisa"]
        penalty_cost = violations * costs["compliance_penalty_paisa"]
        friction_cost = morphs * costs["session_friction_paisa"]

        # Recomputing the aggregate from the aggregate components and asserting
        # it matches the sum of the per-incident values is a cheap standing
        # proof that nothing in the accounting drifted.
        rebuilt = nrcv_paisa(gross, retries, comms, violations, morphs, costs)
        if rebuilt != total_nrcv:
            raise AssertionError(
                f"benchmark: NRCV accounting disagrees for {name}: {rebuilt} != {total_nrcv}"
            )

        policies_out.append({
            "name": name,
            "incidents": int(len(subset)),
            "recovered_incidents": recovered_count,
            "recovery_rate": round(recovered_count / len(subset), 6),
            "gross_recovered_paisa": gross,
            "gross_recovered_display": format_paisa(gross),
            "retries": retries,
            "comms_messages": comms,
            "morphs": morphs,
            "violations": violations,
            "gateway_fee_paisa": gateway_cost,
            "gateway_fee_display": format_paisa(gateway_cost),
            "comms_cost_paisa": comms_cost,
            "comms_cost_display": format_paisa(comms_cost),
            "compliance_penalty_paisa": penalty_cost,
            "compliance_penalty_display": format_paisa(penalty_cost),
            "friction_paisa": friction_cost,
            "friction_display": format_paisa(friction_cost),
            "nrcv_paisa": total_nrcv,
            "nrcv_display": format_paisa(total_nrcv),
        })

    by_name = {entry["name"]: entry for entry in policies_out}
    treatment = by_name[TREATMENT_POLICY]
    baselines = [entry for entry in policies_out if entry["name"] != TREATMENT_POLICY]
    # The strongest baseline is whichever one actually scored highest. Choosing
    # it after the fact, by measurement, removes the objection that we picked a
    # convenient opponent.
    strongest = max(baselines, key=lambda entry: entry["nrcv_paisa"])

    treatment_vector = per_policy[TREATMENT_POLICY]
    baseline_vector = per_policy[strongest["name"]]
    diffs = treatment_vector - baseline_vector

    ci_low_mean, ci_high_mean = paired_bootstrap_ci(diffs, resamples, seed)
    p_value = paired_permutation_p(diffs, permutations, seed)

    n_pairs = int(diffs.size)
    delta_total = int(diffs.sum())
    ci_low_total = int(round(ci_low_mean * n_pairs))
    ci_high_total = int(round(ci_high_mean * n_pairs))
    wins = int(np.count_nonzero(diffs > 0))
    losses = int(np.count_nonzero(diffs < 0))

    # Exact integer decomposition of the headline difference. Each component is
    # that line item contribution to the delta, so the five sum to it exactly.
    # The identity is asserted rather than assumed: it is the cheapest available
    # proof that the attribution a reader acts on is the same arithmetic as the
    # number in the table.
    components = {
        "gross_recovery": treatment["gross_recovered_paisa"] - strongest["gross_recovered_paisa"],
        "gateway_fees": strongest["gateway_fee_paisa"] - treatment["gateway_fee_paisa"],
        "comms": strongest["comms_cost_paisa"] - treatment["comms_cost_paisa"],
        "compliance_penalties": strongest["compliance_penalty_paisa"] - treatment["compliance_penalty_paisa"],
        "session_friction": strongest["friction_paisa"] - treatment["friction_paisa"],
    }
    if sum(components.values()) != delta_total:
        raise AssertionError(
            f"benchmark: delta decomposition sums to {sum(components.values())}, expected {delta_total}"
        )

    comparison = {
        "treatment": TREATMENT_POLICY,
        "baseline": strongest["name"],
        "baseline_selection": "highest measured NRCV among the three baselines",
        "paired": True,
        "n_pairs": n_pairs,
        "treatment_nrcv_paisa": treatment["nrcv_paisa"],
        "baseline_nrcv_paisa": strongest["nrcv_paisa"],
        "delta_paisa": delta_total,
        "delta_display": format_signed_paisa(delta_total),
        "mean_delta_paisa": round(float(diffs.mean()), 4),
        "ci_low_paisa": ci_low_total,
        "ci_high_paisa": ci_high_total,
        "ci_low_display": format_signed_paisa(ci_low_total),
        "ci_high_display": format_signed_paisa(ci_high_total),
        "ci_level_bp": 10_000 - CI_ALPHA_BP,
        "ci_display": (
            f"{format_signed_paisa(ci_low_total)} to {format_signed_paisa(ci_high_total)} "
            f"total NRCV over {n_pairs} paired incidents "
            f"({resamples} paired bootstrap resamples)"
        ),
        "ci_method": "percentile bootstrap over per-incident paired NRCV differences",
        "bootstrap_resamples": int(resamples),
        "p_value": round(p_value, 6),
        "p_value_method": "two-sided paired sign-flip permutation test",
        "permutations": int(permutations),
        "incidents_improved": wins,
        "incidents_worsened": losses,
        "recovery_rate_delta": round(treatment["recovery_rate"] - strongest["recovery_rate"], 6),
        "recovery_only_delta_paisa": components["gross_recovery"],
        "recovery_only_delta_display": format_signed_paisa(components["gross_recovery"]),
        "compliance_penalty_delta_paisa": components["compliance_penalties"],
        "compliance_penalty_delta_display": format_signed_paisa(components["compliance_penalties"]),
        "delta_components_paisa": components,
        "delta_components_display": {
            key: format_signed_paisa(value) for key, value in components.items()
        },
    }

    if commit is None:
        commit = git_commit()

    return {
        "schema_version": SCHEMA_VERSION,
        "seed": int(seed),
        "incidents": int(incident_count),
        "generator_version": GENERATOR_VERSION,
        "cost_model": {key: costs[key] for key in COST_KEYS},
        "currency": "INR",
        "money_unit": "paisa",
        "policies": policies_out,
        "comparison": comparison,
        "manifest": build_manifest(seed, incidents, costs, commit),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(report: dict[str, Any]) -> str:
    comparison = report["comparison"]
    lines = [
        "## ResilientMesh recovery benchmark",
        "",
        f"{report['incidents']} incidents, seed {report['seed']}, "
        f"generator {report['generator_version']}. All money is integer paisa.",
        "",
        "| Policy | Recovered | Recovery rate | Retries | Violations | Net recovered value |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for policy in report["policies"]:
        lines.append(
            f"| {policy['name']} | {policy['gross_recovered_display']} "
            f"| {policy['recovery_rate'] * 100:.1f}% | {policy['retries']} "
            f"| {policy['violations']} | **{policy['nrcv_display']}** |"
        )
    lines += [
        "",
        f"Strongest baseline by measured NRCV: **{comparison['baseline']}**. "
        f"Difference {comparison['delta_display']} "
        f"({comparison['incidents_improved']} incidents improved, "
        f"{comparison['incidents_worsened']} worsened, "
        f"recovery rate {comparison['recovery_rate_delta'] * 100:+.1f} pp).",
        "",
        f"- Paired 95% CI: {comparison['ci_display']}",
        f"- p = {comparison['p_value']:.6f} ({comparison['p_value_method']}, "
        f"{comparison['permutations']} permutations)",
        "",
        "| Delta component | Contribution |",
        "|---|---:|",
    ]
    for key, display in comparison["delta_components_display"].items():
        lines.append(f"| {key.replace('_', ' ')} | {display} |")
    lines += [
        f"| **total** | **{comparison['delta_display']}** |",
        "",
        f"Attestation sha256 `{report['manifest']['hash']}`",
    ]
    return "\n".join(lines)


def write_report(report: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Written with a trailing newline and stable key order so two runs of the
    # same inputs produce byte-identical files, not merely equal ones.
    out_path.write_text(
        json.dumps(report, indent=2, sort_keys=False, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _positive_int(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{raw!r} is not an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"{value} must be at least 1")
    return value


def _seed_int(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{raw!r} is not an integer") from exc
    if value < 0 or value > (1 << 63) - 1:
        raise argparse.ArgumentTypeError(f"{value} is outside [0, 2^63-1]")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmark.py",
        description=(
            "Compare blind retry, static rules, incumbent smart retry and ResilientMesh "
            "over one seeded incident corpus, with a paired bootstrap CI, a paired "
            "permutation test, and a reproducible attestation hash."
        ),
    )
    parser.add_argument(
        "--incidents", type=_positive_int, default=DEFAULT_INCIDENTS,
        help=f"number of incidents to draw (default {DEFAULT_INCIDENTS})",
    )
    parser.add_argument(
        "--seed", type=_seed_int, default=DEFAULT_SEED,
        help=f"generator and resampling seed (default {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help=f"path for the JSON report (default {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="suppress the markdown table on stdout; still writes the report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run(incident_count=args.incidents, seed=args.seed)
    except (OSError, ValueError) as exc:
        print(f"benchmark: {exc}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = Path(os.getcwd()) / out_path
    write_report(report, out_path)

    if not args.quiet:
        print(render_markdown(report))
        print()
        print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
