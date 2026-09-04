#!/usr/bin/env python3
"""ResilientMesh analytical console.

Deliberately thin. The live operational surface is the Go console at
``/console`` — incidents, issuer health, breaker state and the audit chain with
its Verify button all belong there, next to the data and behind the ops token.
This page answers a different question: *did the recovery policy actually win,
and by how much, with what uncertainty?* That is an offline, after-the-fact
question, which is why it reads a benchmark artifact rather than a live stream.

Run it::

    streamlit run dashboard/app.py

or, without Streamlit installed, get the same numbers as text::

    python dashboard/app.py --check

Inputs
------
``artifacts/benchmark.json`` written by ``eval/benchmark.py``, and — when it is
reachable — the ops API for the inference-tier distribution of the *running*
process. The canonical artifact shape is::

    {
      "schema": "resilientmesh.benchmark.v1",
      "seed": 42, "incidents": 500,
      "attestation": {"manifest_sha256": "..."},
      "policies": [
        {"name": "blind_retry", "label": "Blind retry",
         "nrcv_paisa": 12345678, "nrcv_ci95_paisa": [11000000, 13500000],
         "recovery_rate": 0.21, "retries": 903,
         "compliance_violations": 37,
         "inference_tiers": {"LIVE": 0, "REPLAY": 412, "HEURISTIC": 88}}
      ],
      "comparisons": [
        {"baseline": "blind_retry", "treatment": "resilient_mesh",
         "delta_paisa": 8100000, "ci95_paisa": [6900000, 9300000],
         "p_value": 0.0004}
      ],
      "inference_tiers": {"LIVE": 0, "REPLAY": 412, "HEURISTIC": 88, "SKIPPED": 0}
    }

Common alternative key spellings are accepted, because a dashboard that dies on
a renamed field is a dashboard nobody trusts during a demo. Anything genuinely
missing is reported as a note on the page, never as a traceback.

Money is int64 paisa everywhere, exactly as in Go. The only float conversion is
in ``rupees_for_axis``, which exists solely so a chart axis reads in rupees.

Dependencies: Python 3.12 stdlib, numpy/pandas, Streamlit. Plotly is optional
and its absence degrades to ``st.bar_chart`` rather than failing the import.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Sequence

import pandas as pd

try:  # Plotly draws the confidence intervals as real error bars.
    import plotly.graph_objects as go

    HAVE_PLOTLY = True
except ImportError:  # pragma: no cover - exercised by running without plotly
    go = None
    HAVE_PLOTLY = False

DEFAULT_BENCHMARK = os.path.join("artifacts", "benchmark.json")
DEFAULT_OPS_BASE = "http://127.0.0.1:8080"
OPS_TOKEN_ENV = "MESH_OPS_TOKEN"

# The artifact is written by a local process, but it is still a file off disk:
# a corrupt or enormous one must produce a message, not an OOM.
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_OPS_BYTES = 4 * 1024 * 1024
OPS_TIMEOUT_S = 2.0

TIER_ORDER = ("LIVE", "REPLAY", "HEURISTIC", "SKIPPED")


# ---------------------------------------------------------------------------
# Artifact model
# ---------------------------------------------------------------------------


def pick(d: dict[str, Any], *keys: str) -> Any:
    """First present key, or None. The tolerance is the point."""
    for k in keys:
        if isinstance(d, dict) and d.get(k) is not None:
            return d[k]
    return None


@dataclass
class Policy:
    name: str
    label: str
    nrcv_paisa: int | None = None
    ci_low_paisa: int | None = None
    ci_high_paisa: int | None = None
    recovery_rate: float | None = None
    retries: int | None = None
    violations: int | None = None
    tiers: dict[str, int] = field(default_factory=dict)

    @property
    def has_ci(self) -> bool:
        return self.ci_low_paisa is not None and self.ci_high_paisa is not None


@dataclass
class Comparison:
    baseline: str
    treatment: str
    delta_paisa: int | None
    ci_low_paisa: int | None
    ci_high_paisa: int | None
    p_value: float | None
    pairs: int | None = None
    method: str | None = None

    @property
    def has_ci(self) -> bool:
        return self.ci_low_paisa is not None and self.ci_high_paisa is not None


@dataclass
class Report:
    policies: list[Policy]
    comparisons: list[Comparison]
    tiers: dict[str, int]
    meta: dict[str, Any]
    notes: list[str]


def as_paisa(value: Any, label: str, notes: list[str]) -> int | None:
    """Coerce a money field to int paisa, complaining if it arrived as a float.

    Money is integer paisa on both sides of the system. A float here is not a
    formatting quirk, it is evidence that something upstream did money maths in
    floating point, and that is worth saying out loud on the page rather than
    rounding away silently.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != int(value):
            notes.append(f"{label} arrived as a non-integer ({value!r}); money must be int64 paisa")
        return int(round(value))
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        notes.append(f"{label} is not a number ({value!r})")
        return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def interval(entry: dict[str, Any], notes: list[str], label: str,
             *pair_keys: str) -> tuple[int | None, int | None]:
    """Read a 95% interval written either as a pair or as two scalars."""
    for key in pair_keys:
        raw = entry.get(key)
        if isinstance(raw, (list, tuple)) and len(raw) == 2:
            return (as_paisa(raw[0], f"{label} lower bound", notes),
                    as_paisa(raw[1], f"{label} upper bound", notes))
        if isinstance(raw, dict):
            return (as_paisa(pick(raw, "low", "lower", "lo"), f"{label} lower bound", notes),
                    as_paisa(pick(raw, "high", "upper", "hi"), f"{label} upper bound", notes))
    lo = as_paisa(pick(entry, "nrcv_ci95_low_paisa", "ci95_low_paisa", "ci_low_paisa"),
                  f"{label} lower bound", notes)
    hi = as_paisa(pick(entry, "nrcv_ci95_high_paisa", "ci95_high_paisa", "ci_high_paisa"),
                  f"{label} upper bound", notes)
    return lo, hi


# The benchmark's policy identifiers, spelled the way a person would read them.
# Anything not listed falls back to sentence case, which is right for a new arm
# nobody has taught this page about yet.
POLICY_LABELS = {
    "blind_retry": "Blind retry",
    "static_rules": "Static rules",
    "incumbent_smart_retry": "Incumbent smart retry",
    "resilientmesh": "ResilientMesh",
    "resilient_mesh": "ResilientMesh",
    "mesh": "ResilientMesh",
}


def humanise(name: str) -> str:
    key = str(name).strip().lower()
    if key in POLICY_LABELS:
        return POLICY_LABELS[key]
    return key.replace("_", " ").replace("-", " ").strip().capitalize()


def normalise_tiers(raw: Any) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in raw.items():
        n = as_int(value)
        if n is not None:
            out[str(key).upper()] = n
    return out


def parse_policies(doc: dict[str, Any], notes: list[str]) -> list[Policy]:
    raw = pick(doc, "policies", "results", "arms")
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(raw, list):
        for i, e in enumerate(raw):
            if isinstance(e, dict):
                entries.append((str(pick(e, "name", "policy", "id") or f"policy_{i}"), e))
    elif isinstance(raw, dict):
        # A dict keyed by policy name is sorted so the chart order is stable
        # across runs; dict order in JSON is not something to rely on.
        for name in sorted(raw):
            if isinstance(raw[name], dict):
                entries.append((name, raw[name]))
    else:
        notes.append("no 'policies' array in the artifact")
        return []

    policies: list[Policy] = []
    for name, e in entries:
        label = str(pick(e, "label", "display_name") or humanise(name))
        nrcv = as_paisa(pick(e, "nrcv_paisa", "nrcv", "net_recovered_value_paisa",
                             "net_recovered_value"), f"{label} NRCV", notes)
        lo, hi = interval(e, notes, f"{label} NRCV CI",
                          "nrcv_ci95_paisa", "ci95_paisa", "nrcv_ci95", "ci95")

        rate = as_float(pick(e, "recovery_rate", "recovered_rate"))
        if rate is None:
            recovered, total = as_int(pick(e, "recovered", "recoveries")), as_int(
                pick(e, "incidents", "n", "count"))
            if recovered is not None and total:
                rate = recovered / total
        if rate is not None and rate > 1.0:
            # Reported as a percentage rather than a fraction.
            rate = rate / 100.0

        policies.append(Policy(
            name=name,
            label=label,
            nrcv_paisa=nrcv,
            ci_low_paisa=lo,
            ci_high_paisa=hi,
            recovery_rate=rate,
            retries=as_int(pick(e, "retries", "retry_count", "attempts", "total_attempts")),
            violations=as_int(pick(e, "compliance_violations", "violations")),
            tiers=normalise_tiers(pick(e, "inference_tiers", "tier_distribution", "tiers")),
        ))
    return policies


def parse_comparisons(doc: dict[str, Any], notes: list[str]) -> list[Comparison]:
    raw = pick(doc, "comparisons", "comparison", "significance", "paired_tests")
    # A single headline comparison is written as one object; a full matrix as a
    # list. Both are reasonable, so both are read.
    entries = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    out: list[Comparison] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        lo, hi = interval(e, notes, "delta CI", "ci95_paisa", "ci95", "delta_ci95_paisa")
        out.append(Comparison(
            baseline=str(pick(e, "baseline", "control", "a") or "?"),
            treatment=str(pick(e, "treatment", "candidate", "b") or "?"),
            delta_paisa=as_paisa(pick(e, "delta_paisa", "delta", "difference_paisa"),
                                 "delta", notes),
            ci_low_paisa=lo,
            ci_high_paisa=hi,
            p_value=as_float(pick(e, "p_value", "p", "pvalue")),
            pairs=as_int(pick(e, "n_pairs", "pairs", "n")),
            method=str(pick(e, "ci_method", "method") or "") or None,
        ))
    return out


def normalise(doc: dict[str, Any]) -> Report:
    notes: list[str] = []
    policies = parse_policies(doc, notes)

    tiers = normalise_tiers(pick(doc, "inference_tiers", "tier_distribution", "tiers"))
    if not tiers:
        # Fall back to summing the per-policy counts, which is what a benchmark
        # that reports tiers per arm rather than once will have.
        summed: dict[str, int] = {}
        for p in policies:
            for tier, n in p.tiers.items():
                summed[tier] = summed.get(tier, 0) + n
        tiers = summed

    unit = pick(doc, "money_unit", "units")
    if unit is not None and str(unit).strip().lower() != "paisa":
        # Every number on this page is read as int64 paisa. An artifact that
        # says otherwise would be silently mis-scaled by a factor of 100.
        notes.append(f"artifact declares money_unit={unit!r}; this page reads int64 paisa")

    meta = {
        "schema": pick(doc, "schema", "schema_version", "version"),
        "seed": as_int(pick(doc, "seed")),
        "incidents": as_int(pick(doc, "incidents", "n_incidents", "sample_size")),
        "generated_at": pick(doc, "generated_at", "created_at", "timestamp"),
        "code_version": pick(doc, "generator_version", "code_version", "commit", "git_sha"),
        "attestation": pick(doc, "attestation", "manifest"),
        "cost_model": pick(doc, "cost_model", "costs"),
        "currency": pick(doc, "currency"),
    }
    return Report(policies=policies, comparisons=parse_comparisons(doc, notes),
                  tiers=tiers, meta=meta, notes=notes)


def load_benchmark(path: str) -> tuple[Report | None, str | None]:
    """Read the artifact. Returns (report, human-readable problem)."""
    if not os.path.exists(path):
        return None, (
            f"No benchmark artifact at {path}. Produce one with:\n"
            f"    python eval/benchmark.py --incidents 500 --seed 42 --out {path}\n"
            f"or run the full harness: ./scripts/judge.sh")
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, f"Cannot stat {path}: {exc}"
    if size > MAX_ARTIFACT_BYTES:
        return None, f"{path} is {size} bytes, past the {MAX_ARTIFACT_BYTES} byte cap; refusing to load it."
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"Cannot read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
    if not isinstance(doc, dict):
        return None, f"{path} holds a {type(doc).__name__}, expected a JSON object."

    report = normalise(doc)
    if not report.policies:
        return None, (f"{path} parsed but contains no policy results. "
                      "Expected a 'policies' array; see the module docstring for the schema.")
    return report, None


# ---------------------------------------------------------------------------
# Ops API
# ---------------------------------------------------------------------------


def fetch_ops(base: str, path: str, token: str | None,
              timeout: float = OPS_TIMEOUT_S) -> tuple[Any, str | None]:
    """GET one ops endpoint. Never raises; the console is optional by design."""
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_OPS_BYTES)
        return json.loads(body.decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return None, f"{path} refused the credential (HTTP {exc.code}); set {OPS_TOKEN_ENV}."
        return None, f"{path} returned HTTP {exc.code}."
    except urllib.error.URLError as exc:
        return None, f"ops API unreachable at {base}: {exc.reason}"
    except (TimeoutError, OSError) as exc:
        return None, f"ops API unreachable at {base}: {exc}"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, f"{path} did not return JSON."


def tiers_from_metrics(metrics: Any) -> dict[str, int]:
    """Pull the inference-tier counters out of whatever /ops/metrics returns.

    A silent drift from LIVE or REPLAY to HEURISTIC is a quality regression
    that shows up nowhere else, which is why it gets its own panel.
    """
    if not isinstance(metrics, dict):
        return {}
    for key in ("inference_tiers", "inference_tier", "tier_distribution", "diagnose_mode"):
        found = normalise_tiers(metrics.get(key))
        if found:
            return found
    counters = metrics.get("counters")
    if isinstance(counters, dict):
        out: dict[str, int] = {}
        for name, value in counters.items():
            lowered = str(name).lower()
            for tier in TIER_ORDER:
                if lowered.endswith(tier.lower()) and ("tier" in lowered or "mode" in lowered
                                                       or "inference" in lowered):
                    n = as_int(value)
                    if n is not None:
                        out[tier] = out.get(tier, 0) + n
        return out
    return {}


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------


def rupees_for_axis(paisa: int | None) -> float | None:
    """Paisa to rupees, for a chart axis only.

    This is the single float conversion in the file and it is display-only:
    every stored value, every delta and every interval bound stays int64 paisa,
    so nothing that is ever compared or summed passes through here.
    """
    return None if paisa is None else paisa / 100.0


def format_rupees(paisa: int | None) -> str:
    """Exact rupee rendering with integer arithmetic, no float anywhere."""
    if paisa is None:
        return "-"
    sign = "-" if paisa < 0 else ""
    whole, frac = divmod(abs(paisa), 100)
    return f"{sign}Rs {whole:,}.{frac:02d}"


def policy_frame(policies: Sequence[Policy]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Policy": p.label,
        "NRCV": format_rupees(p.nrcv_paisa),
        "95% CI": (f"{format_rupees(p.ci_low_paisa)} to {format_rupees(p.ci_high_paisa)}"
                   if p.has_ci else "not reported"),
        "Recovery rate": "-" if p.recovery_rate is None else f"{p.recovery_rate * 100:.1f}%",
        "Retries": "-" if p.retries is None else f"{p.retries:,}",
        "Compliance violations": "-" if p.violations is None else f"{p.violations:,}",
    } for p in policies])


def simple_frame(policies: Sequence[Policy], attr: str, column: str) -> pd.DataFrame:
    rows = [(p.label, getattr(p, attr)) for p in policies if getattr(p, attr) is not None]
    if not rows:
        return pd.DataFrame(columns=[column])
    return pd.DataFrame({column: [v for _, v in rows]}, index=[k for k, _ in rows])


def nrcv_chart(st, policies: Sequence[Policy]) -> None:
    """NRCV per policy with the bootstrap interval drawn on the bar.

    The interval is the whole point. A bare bar chart of four point estimates
    invites a reader to believe a difference that the data may not support, so
    when the CI is missing the page says so instead of quietly drawing bars
    that look certain.
    """
    priced = [p for p in policies if p.nrcv_paisa is not None]
    if not priced:
        st.info("No NRCV values in the artifact.")
        return

    if HAVE_PLOTLY:
        labels = [p.label for p in priced]
        values = [rupees_for_axis(p.nrcv_paisa) for p in priced]
        upper, lower = [], []
        for p in priced:
            if p.has_ci and p.nrcv_paisa is not None:
                upper.append(rupees_for_axis(p.ci_high_paisa - p.nrcv_paisa))
                lower.append(rupees_for_axis(p.nrcv_paisa - p.ci_low_paisa))
            else:
                upper.append(0.0)
                lower.append(0.0)
        fig = go.Figure(go.Bar(
            x=labels, y=values,
            error_y={"type": "data", "symmetric": False, "array": upper,
                     "arrayminus": lower, "thickness": 1.4, "width": 8},
            hovertemplate="%{x}<br>NRCV Rs %{y:,.2f}<extra></extra>",
        ))
        fig.update_layout(
            yaxis_title="Net recovered value (Rs)", xaxis_title="",
            margin={"l": 8, "r": 8, "t": 8, "b": 8}, height=380, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("plotly is not installed, so the interval is shown in the table "
                   "instead of as an error bar: pip install plotly")
        st.bar_chart(pd.DataFrame(
            {"NRCV (Rs)": [rupees_for_axis(p.nrcv_paisa) for p in priced]},
            index=[p.label for p in priced]))

    if not all(p.has_ci for p in priced):
        st.caption("These bars are point estimates with no interval of their own. The "
                   "evidence for a difference is the paired comparison below: a paired "
                   "bootstrap bounds the *difference* between two policies run over the "
                   "same incidents, and says nothing about either level on its own.")


def delta_chart(st, comparisons: Sequence[Comparison]) -> None:
    """The paired delta with its 95% interval drawn as an error bar.

    This is the chart that carries the claim. Bars whose interval crosses zero
    are shown crossing zero rather than quietly omitted, because an
    inconclusive comparison is a result.
    """
    priced = [c for c in comparisons if c.delta_paisa is not None]
    if not priced:
        st.info("No paired comparison in the artifact.")
        return

    if HAVE_PLOTLY:
        labels = [f"{humanise(c.treatment)}<br>vs {humanise(c.baseline)}" for c in priced]
        values = [rupees_for_axis(c.delta_paisa) for c in priced]
        upper, lower = [], []
        for c in priced:
            if c.has_ci:
                upper.append(rupees_for_axis(c.ci_high_paisa - c.delta_paisa))
                lower.append(rupees_for_axis(c.delta_paisa - c.ci_low_paisa))
            else:
                upper.append(0.0)
                lower.append(0.0)
        fig = go.Figure(go.Bar(
            x=labels, y=values,
            error_y={"type": "data", "symmetric": False, "array": upper,
                     "arrayminus": lower, "thickness": 1.4, "width": 10},
            hovertemplate="%{x}<br>delta Rs %{y:,.2f}<extra></extra>",
        ))
        fig.add_hline(y=0, line_width=1, line_dash="dot")
        fig.update_layout(yaxis_title="Delta NRCV (Rs), 95% paired bootstrap CI",
                          xaxis_title="", margin={"l": 8, "r": 8, "t": 8, "b": 8},
                          height=340, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("plotly is not installed, so the interval is in the table below "
                   "rather than on the bar: pip install plotly")
        st.bar_chart(pd.DataFrame(
            {"Delta NRCV (Rs)": [rupees_for_axis(c.delta_paisa) for c in priced]},
            index=[f"{humanise(c.treatment)} vs {humanise(c.baseline)}" for c in priced]))

    for c in priced:
        if c.has_ci and c.ci_low_paisa <= 0 <= c.ci_high_paisa:
            st.warning(f"The interval for {humanise(c.treatment)} vs "
                       f"{humanise(c.baseline)} spans zero: this run does not "
                       "establish a difference.")


def bar_panel(st, policies: Sequence[Policy], attr: str, column: str, empty: str) -> None:
    frame = simple_frame(policies, attr, column)
    if frame.empty:
        st.info(empty)
        return
    st.bar_chart(frame)


def tier_panel(st, tiers: dict[str, int], source: str) -> None:
    if not tiers:
        st.info("No inference-tier counts available. The benchmark reports them per run, "
                "and a live process reports them on /api/v1/ops/metrics.")
        return
    ordered = [t for t in TIER_ORDER if t in tiers] + sorted(set(tiers) - set(TIER_ORDER))
    st.bar_chart(pd.DataFrame({"Diagnoses": [tiers[t] for t in ordered]}, index=ordered))
    total = sum(tiers.values())
    heuristic = tiers.get("HEURISTIC", 0)
    st.caption(f"Source: {source}. {total:,} diagnoses.")
    if total and heuristic / total > 0.5:
        st.warning(f"{heuristic:,} of {total:,} diagnoses came from the heuristic tier. "
                   "A drift to HEURISTIC is a quality regression, not a fallback working "
                   "as intended.")


def comparison_frame(comparisons: Sequence[Comparison]) -> pd.DataFrame:
    return pd.DataFrame([{
        "Comparison": f"{humanise(c.treatment)} vs {humanise(c.baseline)}",
        "Delta NRCV": format_rupees(c.delta_paisa),
        "95% CI": (f"{format_rupees(c.ci_low_paisa)} to {format_rupees(c.ci_high_paisa)}"
                   if c.ci_low_paisa is not None and c.ci_high_paisa is not None
                   else "not reported"),
        "p": "-" if c.p_value is None else f"{c.p_value:.4g}",
        "Pairs": "-" if c.pairs is None else f"{c.pairs:,}",
    } for c in comparisons])


# ---------------------------------------------------------------------------
# Streamlit page
# ---------------------------------------------------------------------------


def render(args: argparse.Namespace) -> None:
    import streamlit as st

    st.set_page_config(page_title="ResilientMesh - recovery analytics", layout="wide")
    st.title("ResilientMesh recovery analytics")
    st.caption("Offline analysis of a benchmark run. Live incidents, issuer health, "
               "breaker state and the audit chain live in the Go console at /console.")

    report, problem = load_benchmark(args.benchmark)
    if report is None:
        # The artifact is absent on a fresh checkout and mid-run during the
        # judge harness. Both are normal, so both get an instruction rather
        # than a traceback.
        st.info(problem)
        st.stop()
        return

    meta = report.meta
    cols = st.columns(4)
    cols[0].metric("Incidents", f"{meta['incidents']:,}" if meta["incidents"] else "-")
    cols[1].metric("Seed", str(meta["seed"]) if meta["seed"] is not None else "-")
    cols[2].metric("Policies", str(len(report.policies)))
    best = max((p for p in report.policies if p.nrcv_paisa is not None),
               key=lambda p: p.nrcv_paisa, default=None)
    cols[3].metric("Best NRCV", format_rupees(best.nrcv_paisa) if best else "-",
                   help=best.label if best else None)

    for note in report.notes:
        st.warning(note)

    st.subheader("Net recovered value by policy")
    nrcv_chart(st, report.policies)
    st.dataframe(policy_frame(report.policies), use_container_width=True, hide_index=True)

    if report.comparisons:
        st.subheader("Paired comparison, with the 95% interval as an error bar")
        st.caption("Paired bootstrap over the same incident set: each policy sees the "
                   "identical incidents, so the difference is measured within pairs "
                   "rather than between two independent samples.")
        delta_chart(st, report.comparisons)
        st.dataframe(comparison_frame(report.comparisons),
                     use_container_width=True, hide_index=True)
        methods = sorted({c.method for c in report.comparisons if c.method})
        for m in methods:
            st.caption(f"Interval method: {m}")

    left, right = st.columns(2)
    with left:
        st.subheader("Recovery rate")
        bar_panel(st, report.policies, "recovery_rate", "Recovery rate",
                  "No recovery rates in the artifact.")
    with right:
        st.subheader("Retries")
        st.caption("Retries are a cost, not an achievement: each one is a gateway fee "
                   "and a chance to annoy an issuer.")
        bar_panel(st, report.policies, "retries", "Retries", "No retry counts in the artifact.")

    st.subheader("Compliance violations")
    st.caption("This is an invariant, not an objective. Any non-zero bar for ResilientMesh "
               "is a defect, and the gatekeeper property tests exist to keep it at zero.")
    bar_panel(st, report.policies, "violations", "Violations",
              "No compliance-violation counts in the artifact.")

    st.subheader("Inference-tier distribution")
    tiers, source = report.tiers, "benchmark artifact"
    if args.ops:
        metrics, ops_problem = fetch_ops(args.ops, "/api/v1/ops/metrics",
                                         os.environ.get(OPS_TOKEN_ENV))
        if ops_problem:
            st.caption(f"Live ops API not used: {ops_problem}")
        else:
            live = tiers_from_metrics(metrics)
            if live:
                tiers, source = live, f"live ops API at {args.ops}"
    tier_panel(st, tiers, source)

    attestation = meta.get("attestation")
    if attestation:
        with st.expander("Attestation manifest"):
            st.caption("Re-derive it with: meshctl bench verify --manifest "
                       f"{args.benchmark}")
            st.json(attestation)


# ---------------------------------------------------------------------------
# Text mode
# ---------------------------------------------------------------------------


def check(args: argparse.Namespace) -> int:
    """Print the same numbers as text, with no Streamlit and no plotting.

    The judge harness runs headless, and "install Streamlit to find out whether
    the benchmark parsed" is not an acceptable answer during a review.
    """
    report, problem = load_benchmark(args.benchmark)
    if report is None:
        print(problem)
        return 1

    meta = report.meta
    print(f"benchmark : {args.benchmark}")
    print(f"schema    : {meta['schema'] or '(unstated)'}")
    print(f"seed      : {meta['seed'] if meta['seed'] is not None else '(unstated)'}"
          f"   incidents: {meta['incidents'] or '(unstated)'}")
    print()
    frame = policy_frame(report.policies)
    print(frame.to_string(index=False))
    if report.comparisons:
        print()
        print(comparison_frame(report.comparisons).to_string(index=False))
    if report.tiers:
        print()
        ordered = [t for t in TIER_ORDER if t in report.tiers]
        ordered += sorted(set(report.tiers) - set(TIER_ORDER))
        print("inference tiers: " + ", ".join(f"{t}={report.tiers[t]:,}" for t in ordered))
    attestation = meta.get("attestation")
    if isinstance(attestation, dict):
        digest = pick(attestation, "hash", "manifest_sha256", "sha256", "digest")
        if digest:
            print(f"attestation: {digest}")
    for note in report.notes:
        print(f"note: {note}")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="app.py",
        description="ResilientMesh analytical console (Streamlit). "
                    "Run with: streamlit run dashboard/app.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--benchmark", default=DEFAULT_BENCHMARK,
                   help="path to the benchmark artifact")
    p.add_argument("--ops", default=DEFAULT_OPS_BASE,
                   help="ops API base URL; pass an empty string to skip it")
    p.add_argument("--check", action="store_true",
                   help="print the numbers as text and exit, without Streamlit")
    # Streamlit puts its own arguments on sys.argv, and an unknown one must not
    # take the page down before it renders.
    known, _ = p.parse_known_args(argv)
    return known


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.check:
        return check(args)
    try:
        render(args)
    except ImportError:
        print("Streamlit is not installed. Either:\n"
              "    pip install streamlit plotly\n"
              "    streamlit run dashboard/app.py\n"
              "or get the same numbers as text with:\n"
              "    python dashboard/app.py --check", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
