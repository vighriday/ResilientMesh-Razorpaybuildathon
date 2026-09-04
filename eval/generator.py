"""Seeded incident generator for the ResilientMesh recovery benchmark.

A policy comparison is only evidence if two properties hold. First, the
incidents must be drawn without knowledge of which policy will be measured.
Second, the ground truth must be genuinely underdetermined by what a policy is
allowed to observe -- otherwise the "smart" policy is just reading the answer
key and a reviewer is right to throw the result out.

Both properties are enforced structurally rather than promised in prose. The
latent cause of every failure lives in an incident "truth" sub-object, and
build_observation is the only view a policy is ever handed: it cannot read the
truth because the truth is not in the dict it receives. What separates a
transient degradation from a permanent one in the observable view is ambient
evidence -- the rolling issuer success rate against its portfolio baseline, and
whether a downtime notice was published -- exactly as it is for the running
system.

Determinism is a hard requirement because the attestation manifest hashes the
incident corpus: the same seed must reconstruct the same bytes on any machine.
Only Generator.integers is used to draw. The higher-level distribution methods
(lognormal and friends) are convenient but their streams are not contractually
frozen across NumPy releases, which would make an attestation hash silently
unreproducible after a dependency bump.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, NamedTuple

import numpy as np

# Bumped whenever a change alters the drawn corpus for a fixed seed. The value
# is attested, so a reviewer can tell a genuine re-run from a moved goalpost.
GENERATOR_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

MINUTE = 60
HOUR = 3600
DAY = 86400

# Fixed epoch anchor (2026-01-01T00:00:00Z). Wall-clock time is deliberately
# absent from generation: a corpus that depends on when it was generated cannot
# be attested.
EPOCH_BASE = 1_767_225_600
HORIZON_SECONDS = 7 * DAY

# A checkout session is abandoned long before this; past it an in-session morph
# has nobody left to morph for.
SESSION_TTL_SECONDS = 900

# ---------------------------------------------------------------------------
# Taxonomy mirrors of internal/domain/models.go
#
# These are duplicated rather than imported because Python cannot read Go
# constants. test_benchmark.py parses the Go source and asserts set equality, so
# the duplication is checked rather than trusted.
# ---------------------------------------------------------------------------

TERMINAL_DECLINE_CODES = frozenset({
    "debit_instrument_blocked",
    "bank_account_invalid",
    "transaction_limit_exceeded",
    "payment_method_not_enabled",
    "invalid_card_number",
    "card_lost_or_stolen",
    "international_transaction_not_allowed",
    "payment_cancelled_by_user",
    "mandate_revoked",
})

REFRESHABLE_DECLINE_CODES = frozenset({"card_expired", "card_not_supported"})

AMBIGUOUS_FAILURE_CODES = frozenset({
    "bank_technical_error",
    "gateway_technical_error",
    "payment_timed_out",
    "server_error",
    "issuer_down",
    "gateway_error",
    "upi_psp_error",
    "payment_pending",
})

SOFT_DECLINE_CODES = frozenset({
    "insufficient_funds",
    "payment_failed",
    "invalid_otp",
    "incorrect_otp",
    "authentication_failed",
    "upi_collect_expired",
    "mandate_not_active",
})

# domain.InstrumentPresentation
P_UNCHANGED = "unchanged"
P_NETWORK_TOKEN = "network_token"
P_STORED_CRED = "stored_credential"
P_FRESH_AUTH = "fresh_authorisation"

# domain.Rail
RAIL_UPI_INTENT = "upi_intent"
RAIL_UPI_COLLECT = "upi_collect"
RAIL_CARD = "card"
RAIL_NETBANKING = "netbanking"
RAIL_WALLET = "wallet"

RAIL_FROM_METHOD = {
    "upi": RAIL_UPI_INTENT,
    "card": RAIL_CARD,
    "emi": RAIL_CARD,
    "netbanking": RAIL_NETBANKING,
    "wallet": RAIL_WALLET,
}

# domain.FailureClass values, used here as the latent cause label.
CLASS_OUTAGE = "ISSUER_OUTAGE"
CLASS_TRANSIENT = "TRANSIENT_ISSUER_DEGRADATION"
CLASS_PERMANENT = "PERMANENT_INSTRUMENT_FAILURE"
CLASS_STALE = "INSTRUMENT_STALE"
CLASS_FUNDS = "INSUFFICIENT_FUNDS"
CLASS_CUSTOMER = "CUSTOMER_ACTION_REQUIRED"

# domain.MandateCategory and its AFA ceilings, in paisa.
AFA_CEILING_GENERAL_PAISA = 15_000_00
AFA_CEILING_ELEVATED_PAISA = 1_00_000_00
ELEVATED_CATEGORIES = frozenset({"insurance", "mutual_fund", "credit_card_bill"})


def afa_ceiling_paisa(category: str) -> int:
    """Ceiling above which a recurring debit needs a fresh additional factor.

    An unrecognised category gets the stricter general ceiling: an unknown
    category must never widen a regulatory limit.
    """
    if category in ELEVATED_CATEGORIES:
        return AFA_CEILING_ELEVATED_PAISA
    return AFA_CEILING_GENERAL_PAISA


# ---------------------------------------------------------------------------
# Mix tables. Weights are per-mille integers so a draw is a single bounded
# integer comparison and the stream stays reproducible.
# ---------------------------------------------------------------------------

METHOD_MIX = (("upi", 620), ("card", 190), ("netbanking", 110), ("wallet", 50), ("emi", 30))

UPI_HANDLE_MIX = (
    ("okhdfcbank", 190), ("oksbi", 175), ("okicici", 130), ("ybl", 120),
    ("okaxis", 110), ("paytm", 105), ("ibl", 90), ("apl", 80),
)
CARD_BANK_MIX = (
    ("HDFC", 230), ("ICIC", 190), ("SBIN", 175), ("UTIB", 140),
    ("KKBK", 90), ("IDFB", 70), ("PUNB", 60), ("BARB", 45),
)
NETBANKING_BANK_MIX = (
    ("SBIN", 260), ("HDFC", 190), ("ICIC", 165), ("UTIB", 130),
    ("PUNB", 95), ("BARB", 85), ("CNRB", 75),
)
WALLET_MIX = (
    ("paytm", 380), ("phonepe", 250), ("mobikwik", 150),
    ("amazonpay", 130), ("freecharge", 90),
)

MANDATE_CATEGORY_MIX = (
    ("general", 700), ("insurance", 120), ("mutual_fund", 120), ("credit_card_bill", 60),
)

# Amount bands in paisa. Indian one-off volume is dominated by small tickets
# with a thin tail. The tail is deliberately bounded near Rs 1.5 lakh: a corpus
# where two draws carry a tenth of total value measures those two draws rather
# than the policies.
ONE_OFF_AMOUNT_BANDS = (
    ((2_000, 49_900), 352),
    ((50_000, 199_900), 350),
    ((200_000, 999_900), 220),
    ((1_000_000, 4_999_900), 70),
    ((5_000_000, 15_000_000), 8),
)

# Recurring amounts are drawn conditional on mandate category, because in this
# market the two are correlated and the correlation is the whole reason the AFA
# framework has two ceilings. A general-category mandate is a subscription or a
# utility bill and lives well under Rs 15,000; insurance premiums, SIPs and
# credit-card bills are larger and are granted the Rs 1,00,000 ceiling. Drawing
# amount independently of category would manufacture Rs 2 lakh gym memberships
# and turn a rare regulatory edge into the dominant term.
RECURRING_GENERAL_AMOUNT_BANDS = (
    ((9_900, 99_900), 450),
    ((100_000, 499_900), 330),
    ((500_000, 1_499_900), 180),
    ((1_500_100, 4_999_900), 40),
)
RECURRING_ELEVATED_AMOUNT_BANDS = (
    ((50_000, 499_900), 350),
    ((500_000, 2_499_900), 350),
    ((2_500_000, 9_999_900), 250),
    ((10_000_100, 15_000_000), 50),
)

OUTAGE_DURATION_MIX = ((15 * MINUTE, 340), (45 * MINUTE, 330), (2 * HOUR, 240), (6 * HOUR, 90))

# Class mixes for incidents that did not arrive inside an issuer outage.
ONE_OFF_CLASS_MIX = (
    (CLASS_TRANSIENT, 220), (CLASS_PERMANENT, 200), (CLASS_FUNDS, 240),
    (CLASS_CUSTOMER, 200), (CLASS_STALE, 140),
)
RECURRING_CLASS_MIX = (
    (CLASS_FUNDS, 460), (CLASS_TRANSIENT, 200), (CLASS_PERMANENT, 180), (CLASS_STALE, 160),
)

ALT_RAIL_MIX = (
    (RAIL_UPI_INTENT, 400), (RAIL_CARD, 300), (RAIL_NETBANKING, 150),
    (RAIL_WALLET, 100), (RAIL_UPI_COLLECT, 50),
)

# Per-class error-code tables. Outage and transient degradation draw from the
# same ambiguous pool on purpose: the code alone must not reveal the cause.
_TRANSIENT_CODES = (
    ("bank_technical_error", 260), ("gateway_technical_error", 210), ("payment_timed_out", 200),
    ("server_error", 140), ("gateway_error", 120), ("payment_pending", 70),
)
_TRANSIENT_CODES_UPI = (
    ("upi_psp_error", 300), ("bank_technical_error", 200), ("payment_timed_out", 200),
    ("gateway_technical_error", 140), ("server_error", 100), ("payment_pending", 60),
)
_OUTAGE_CODES = (
    ("issuer_down", 380), ("bank_technical_error", 250),
    ("gateway_technical_error", 200), ("payment_timed_out", 170),
)
_OUTAGE_CODES_UPI = (
    ("upi_psp_error", 400), ("issuer_down", 260),
    ("bank_technical_error", 180), ("payment_timed_out", 160),
)
_PERMANENT_CODES = (
    ("debit_instrument_blocked", 260), ("bank_account_invalid", 220),
    ("transaction_limit_exceeded", 200), ("payment_method_not_enabled", 170),
    ("payment_cancelled_by_user", 150),
)
_PERMANENT_CODES_CARD = (
    ("invalid_card_number", 260), ("card_lost_or_stolen", 220),
    ("international_transaction_not_allowed", 190), ("debit_instrument_blocked", 180),
    ("transaction_limit_exceeded", 150),
)
_PERMANENT_CODES_RECURRING = (("mandate_revoked", 620), ("bank_account_invalid", 380))
_CUSTOMER_CODES = (
    ("invalid_otp", 300), ("authentication_failed", 280),
    ("incorrect_otp", 200), ("payment_failed", 220),
)
_CUSTOMER_CODES_UPI = (
    ("upi_collect_expired", 420), ("authentication_failed", 220),
    ("invalid_otp", 190), ("payment_failed", 170),
)
_FUNDS_CODES = (("insufficient_funds", 1000),)
_FUNDS_CODES_RECURRING = (("insufficient_funds", 850), ("mandate_not_active", 150))
_STALE_CODES = (("card_expired", 640), ("card_not_supported", 360))

# Shares below are basis points against _roll, which draws [0, 10000).
#
# A slice of genuinely permanent failures hide behind an ambiguous code. Without
# them every ambiguous code would be worth retrying, and the harness would be
# quietly flattering any policy that retries ambiguity aggressively -- including
# ours.
PERMANENT_MASKED_BP = 1800

# Share of incidents deliberately placed inside a live outage window. Failures
# genuinely cluster during outages; drawing arrivals uniformly would produce a
# corpus where outage handling almost never matters.
OUTAGE_CLUSTERED_BP = 4000
OUTAGE_MISLABEL_BP = 1200  # inside a window, but the cause was local rather than the outage
OUTAGE_PUBLISHED_BP = 8500  # share of outages the downtime feed actually announces

RECURRING_SHARE_BP = 1800
SESSION_ACTIVE_BP = 3400
ALT_RAIL_HEALTHY_BP = 7800
ALT_RAIL_OBSERVATION_NOISE_BP = 1000  # telemetry misreads the alternate rail this often

DRAWS_PER_INCIDENT = 8

MAX_INCIDENTS = 200_000
MAX_SEED = (1 << 63) - 1


# Abandonment half-lives. Without a hazard on elapsed time, an NRCV model says a
# retry seven days late is worth exactly as much as one ten seconds late, which
# would silently flatter every patient policy in the comparison -- including
# ours on the recurring rail. The half-life is a property of the recovery
# channel rather than of the failure: a checkout in progress evaporates in
# minutes, a customer chased by a payment link lasts hours, someone whose
# account was simply empty still wants the thing for days, and a mandate is a
# billing relationship that does not abandon at all inside one cycle.
HALF_LIFE_SESSION = (20 * MINUTE, 90 * MINUTE)
HALF_LIFE_ASYNC = (6 * HOUR, 24 * HOUR)
HALF_LIFE_FUNDS = (3 * DAY, 7 * DAY)
HALF_LIFE_MANDATE = (20 * DAY, 40 * DAY)

# Past this many half-lives the retained share underflows the basis-point grid.
MAX_HALVINGS = 16


class Attempt(NamedTuple):
    """One outbound recovery attempt a policy has decided to make.

    This is the contract between a policy, the outcome model, and the compliance
    auditor. A policy declares what it did -- when, on which rail, in which
    presentation, and whether it discharged its notification and authentication
    obligations -- and is then judged on that declaration by rules it does not
    own.
    """

    at: int
    rail: str
    presentation: str
    in_session: bool
    pre_debit_notified: bool
    afa_obtained: bool
    comms_messages: int


# ---------------------------------------------------------------------------
# Bounded weighted draws
# ---------------------------------------------------------------------------


def _validate_table(table: tuple[tuple[Any, int], ...], name: str) -> None:
    total = sum(weight for _, weight in table)
    if total != 1000:
        raise ValueError(f"generator: mix table {name} sums to {total}, expected 1000")


for _name, _table in (
    ("METHOD_MIX", METHOD_MIX), ("UPI_HANDLE_MIX", UPI_HANDLE_MIX),
    ("CARD_BANK_MIX", CARD_BANK_MIX), ("NETBANKING_BANK_MIX", NETBANKING_BANK_MIX),
    ("WALLET_MIX", WALLET_MIX), ("MANDATE_CATEGORY_MIX", MANDATE_CATEGORY_MIX),
    ("OUTAGE_DURATION_MIX", OUTAGE_DURATION_MIX), ("ONE_OFF_CLASS_MIX", ONE_OFF_CLASS_MIX),
    ("RECURRING_CLASS_MIX", RECURRING_CLASS_MIX), ("ALT_RAIL_MIX", ALT_RAIL_MIX),
    ("_TRANSIENT_CODES", _TRANSIENT_CODES), ("_TRANSIENT_CODES_UPI", _TRANSIENT_CODES_UPI),
    ("_OUTAGE_CODES", _OUTAGE_CODES), ("_OUTAGE_CODES_UPI", _OUTAGE_CODES_UPI),
    ("_PERMANENT_CODES", _PERMANENT_CODES), ("_PERMANENT_CODES_CARD", _PERMANENT_CODES_CARD),
    ("_PERMANENT_CODES_RECURRING", _PERMANENT_CODES_RECURRING),
    ("_CUSTOMER_CODES", _CUSTOMER_CODES), ("_CUSTOMER_CODES_UPI", _CUSTOMER_CODES_UPI),
    ("_FUNDS_CODES", _FUNDS_CODES), ("_FUNDS_CODES_RECURRING", _FUNDS_CODES_RECURRING),
    ("_STALE_CODES", _STALE_CODES),
    ("ONE_OFF_AMOUNT_BANDS", ONE_OFF_AMOUNT_BANDS),
    ("RECURRING_GENERAL_AMOUNT_BANDS", RECURRING_GENERAL_AMOUNT_BANDS),
    ("RECURRING_ELEVATED_AMOUNT_BANDS", RECURRING_ELEVATED_AMOUNT_BANDS),
):
    _validate_table(_table, _name)
del _name, _table


def _pick(rng: np.random.Generator, table: tuple[tuple[Any, int], ...]) -> Any:
    roll = int(rng.integers(0, 1000))
    acc = 0
    for value, weight in table:
        acc += weight
        if roll < acc:
            return value
    return table[-1][0]


def _pick_excluding(rng: np.random.Generator, table: tuple[tuple[Any, int], ...], exclude: Any) -> Any:
    allowed = [(value, weight) for value, weight in table if value != exclude]
    total = sum(weight for _, weight in allowed)
    roll = int(rng.integers(0, total))
    acc = 0
    for value, weight in allowed:
        acc += weight
        if roll < acc:
            return value
    return allowed[-1][0]


def _roll(rng: np.random.Generator) -> int:
    return int(rng.integers(0, 10_000))


def _between(rng: np.random.Generator, lo: int, hi: int) -> int:
    return int(rng.integers(lo, hi + 1))


def _issuer_key(rng: np.random.Generator, method: str) -> str:
    """Reproduce domain.PaymentEntity.Issuer exactly.

    Card and netbanking key off the bank code; UPI keys off the VPA handle,
    because UPI outages are PSP-handle scoped rather than bank scoped.
    """
    if method == "upi":
        return "upi:" + _pick(rng, UPI_HANDLE_MIX)
    if method == "wallet":
        return "wallet:" + _pick(rng, WALLET_MIX)
    if method == "netbanking":
        return "netbanking:" + _pick(rng, NETBANKING_BANK_MIX)
    return method + ":" + _pick(rng, CARD_BANK_MIX)


def _draw_amount(rng: np.random.Generator, recurring: bool, category: str) -> int:
    if not recurring:
        bands = ONE_OFF_AMOUNT_BANDS
    elif category in ELEVATED_CATEGORIES:
        bands = RECURRING_ELEVATED_AMOUNT_BANDS
    else:
        bands = RECURRING_GENERAL_AMOUNT_BANDS
    lo, hi = _pick(rng, bands)
    # Whole-rupee amounts, drawn directly as integer paisa. Every downstream
    # operation on money is integer arithmetic; nothing here divides paisa.
    steps = (hi - lo) // 100
    return lo + 100 * _between(rng, 0, steps)


def _draw_code(rng: np.random.Generator, cls: str, method: str, recurring: bool) -> str:
    upi = method == "upi"
    card = method in ("card", "emi")
    if cls == CLASS_OUTAGE:
        return _pick(rng, _OUTAGE_CODES_UPI if upi else _OUTAGE_CODES)
    if cls == CLASS_TRANSIENT:
        return _pick(rng, _TRANSIENT_CODES_UPI if upi else _TRANSIENT_CODES)
    if cls == CLASS_PERMANENT:
        if recurring:
            return _pick(rng, _PERMANENT_CODES_RECURRING)
        return _pick(rng, _PERMANENT_CODES_CARD if card else _PERMANENT_CODES)
    if cls == CLASS_FUNDS:
        return _pick(rng, _FUNDS_CODES_RECURRING if recurring else _FUNDS_CODES)
    if cls == CLASS_CUSTOMER:
        return _pick(rng, _CUSTOMER_CODES_UPI if upi else _CUSTOMER_CODES)
    return _pick(rng, _STALE_CODES)


# ---------------------------------------------------------------------------
# Outage timeline
# ---------------------------------------------------------------------------


def _generate_outages(rng: np.random.Generator, count: int) -> list[dict[str, Any]]:
    """Build the issuer health timeline the whole corpus is drawn against.

    Every outage has a real begin and end. Whether it was *published* is a
    separate draw, because that is precisely the difference between a system
    that waits on a resolution notice and one that estimates recovery
    statistically.
    """
    n_outages = max(4, count // 35)
    outages: list[dict[str, Any]] = []
    for index in range(n_outages):
        method = _pick(rng, METHOD_MIX)
        issuer = _issuer_key(rng, method)
        duration = _pick(rng, OUTAGE_DURATION_MIX)
        begin = EPOCH_BASE + _between(rng, 0, HORIZON_SECONDS - duration - 1)
        if duration >= 2 * HOUR:
            severity = "high"
        elif duration >= 45 * MINUTE:
            severity = "medium"
        else:
            severity = "low"
        outages.append({
            "id": f"down_{index:04d}",
            "telemetry_key": issuer,
            "method": method,
            "begin": begin,
            "end": begin + duration,
            "severity": severity,
            "published": _roll(rng) < OUTAGE_PUBLISHED_BP,
        })
    outages.sort(key=lambda outage: (outage["begin"], outage["id"]))
    return outages


def _active_outage(outages: list[dict[str, Any]], issuer_key: str, ts: int) -> dict[str, Any] | None:
    for outage in outages:
        if outage["telemetry_key"] == issuer_key and outage["begin"] <= ts <= outage["end"]:
            return outage
    return None


# ---------------------------------------------------------------------------
# Incident construction
# ---------------------------------------------------------------------------


def _generate_incident(
    rng: np.random.Generator, index: int, outages: list[dict[str, Any]]
) -> dict[str, Any]:
    if outages and _roll(rng) < OUTAGE_CLUSTERED_BP:
        outage = outages[int(rng.integers(0, len(outages)))]
        method = outage["method"]
        issuer_key = outage["telemetry_key"]
        arrival = outage["begin"] + _between(rng, 0, max(1, outage["end"] - outage["begin"] - 1))
    else:
        method = _pick(rng, METHOD_MIX)
        issuer_key = _issuer_key(rng, method)
        arrival = EPOCH_BASE + _between(rng, 0, HORIZON_SECONDS - 1)
        outage = _active_outage(outages, issuer_key, arrival)

    rail = RAIL_FROM_METHOD[method]
    recurring = _roll(rng) < RECURRING_SHARE_BP
    category = _pick(rng, MANDATE_CATEGORY_MIX) if recurring else "general"
    amount = _draw_amount(rng, recurring, category)

    if outage is not None and _roll(rng) >= OUTAGE_MISLABEL_BP:
        cls = CLASS_OUTAGE
    else:
        cls = _pick(rng, RECURRING_CLASS_MIX if recurring else ONE_OFF_CLASS_MIX)
        # A stale card credential is only a card story. On other rails the same
        # slot is a customer-action failure (one-off) or a funding one (mandate).
        if cls == CLASS_STALE and method not in ("card", "emi"):
            cls = CLASS_FUNDS if recurring else CLASS_CUSTOMER

    code = _draw_code(rng, cls, method, recurring)
    if cls == CLASS_PERMANENT and _roll(rng) < PERMANENT_MASKED_BP:
        # A permanent issuer-side block reported as a generic technical error.
        # No policy can tell this from a transient one; everybody pays for it.
        code = _pick(rng, _OUTAGE_CODES_UPI if method == "upi" else _TRANSIENT_CODES)

    session_active = (not recurring) and _roll(rng) < SESSION_ACTIVE_BP
    session_age = _between(rng, 15, 600) if session_active else 0

    if outage is not None:
        success_rate_bp = _between(rng, 200, 1400)
        attempts = _between(rng, 40, 400)
    else:
        success_rate_bp = _between(rng, 8000, 9700)
        attempts = _between(rng, 3, 400)
    baseline_rate_bp = _between(rng, 8700, 9400)
    # Mirrors domain.TelemetrySnapshot.Degraded: an evidence floor of 8 samples,
    # an absolute rate floor of 0.35, and a peer comparison at half baseline.
    degraded = attempts >= 8 and (success_rate_bp < 3500 or success_rate_bp * 2 < baseline_rate_bp)

    alt_rail = _pick_excluding(rng, ALT_RAIL_MIX, rail)
    alt_healthy = _roll(rng) < ALT_RAIL_HEALTHY_BP
    alt_observed_healthy = alt_healthy
    if _roll(rng) < ALT_RAIL_OBSERVATION_NOISE_BP:
        alt_observed_healthy = not alt_healthy
    alt_rail_bp = _between(rng, 7200, 8500) if alt_healthy else _between(rng, 400, 1600)

    floor_bp = 0
    recovered_bp = 0
    recovery_ts = arrival
    refresh_bp = 0
    if cls == CLASS_OUTAGE:
        floor_bp = _between(rng, 150, 800)
        recovered_bp = _between(rng, 7800, 8900)
        recovery_ts = outage["end"] if outage is not None else arrival
    elif cls == CLASS_TRANSIENT:
        floor_bp = _between(rng, 900, 2200)
        recovered_bp = _between(rng, 7500, 8800)
        recovery_ts = arrival + _between(rng, 60, 1200)
    elif cls == CLASS_FUNDS:
        floor_bp = _between(rng, 300, 1100)
        recovered_bp = _between(rng, 6200, 7800)
        recovery_ts = arrival + _between(rng, 4 * HOUR, 80 * HOUR)
    elif cls == CLASS_CUSTOMER:
        floor_bp = _between(rng, 800, 2000)
        recovered_bp = _between(rng, 5500, 7200)
    elif cls == CLASS_STALE:
        refresh_bp = _between(rng, 5800, 7400)

    # An out-of-band re-authentication link converts at roughly half the uplift
    # of an in-session prompt: the customer has already left the page.
    oob_auth_bp = floor_bp + (recovered_bp - floor_bp) // 2 if cls == CLASS_CUSTOMER else 0

    if recurring:
        half_life = _between(rng, *HALF_LIFE_MANDATE)
    elif cls == CLASS_FUNDS:
        half_life = _between(rng, *HALF_LIFE_FUNDS)
    elif session_active:
        half_life = _between(rng, *HALF_LIFE_SESSION)
    else:
        half_life = _between(rng, *HALF_LIFE_ASYNC)

    draws = [_roll(rng) for _ in range(DRAWS_PER_INCIDENT)]
    ambiguity_roll = _roll(rng)
    timing_noise_bp = _roll(rng)
    attempts_in_cycle_before = (1 if _roll(rng) < 7500 else 2) if recurring else 0

    downtime = None
    if outage is not None and outage["published"]:
        downtime = {
            "id": outage["id"],
            "severity": outage["severity"],
            "status": "started",
            "scheduled": False,
            "begin": outage["begin"],
            "end": outage["end"],
            "matches_issuer": True,
        }

    return {
        "incident_id": f"inc_{index:06d}",
        "payment_id": f"pay_{index:06d}",
        "order_id": f"order_{index:06d}",
        "subscription_id": f"sub_{index:06d}" if recurring else "",
        "method": method,
        "rail": rail,
        "issuer_key": issuer_key,
        "error_code": code,
        "amount_paisa": amount,
        "currency": "INR",
        "is_recurring": recurring,
        "mandate_category": category,
        "attempts_in_cycle_before": attempts_in_cycle_before,
        "session_active": session_active,
        "session_age_seconds": session_age,
        "arrival_ts": arrival,
        "telemetry": {
            "attempts": attempts,
            "success_rate_bp": success_rate_bp,
            "baseline_rate_bp": baseline_rate_bp,
            "degraded": degraded,
        },
        "downtime": downtime,
        "alt_rail": alt_rail,
        "alt_rail_observed_healthy": alt_observed_healthy,
        "ambiguity_roll": ambiguity_roll,
        "timing_noise_bp": timing_noise_bp,
        "draws": draws,
        "truth": {
            "class": cls,
            "outage_id": outage["id"] if outage is not None else "",
            "outage_published": bool(outage["published"]) if outage is not None else False,
            "recovery_ts": recovery_ts,
            "floor_bp": floor_bp,
            "recovered_bp": recovered_bp,
            "oob_auth_bp": oob_auth_bp,
            "alt_rail_bp": alt_rail_bp,
            "alt_rail_healthy": alt_healthy,
            "refresh_bp": refresh_bp,
            "retention_half_life_seconds": half_life,
        },
    }


# Keys a policy is allowed to see. Anything absent from this tuple is latent, so
# a policy that wanted to cheat would have to be edited to accept a different
# argument -- a reviewable change rather than an invisible one.
OBSERVABLE_KEYS = (
    "incident_id", "payment_id", "order_id", "subscription_id", "method", "rail",
    "issuer_key", "error_code", "amount_paisa", "currency", "is_recurring",
    "mandate_category", "attempts_in_cycle_before", "session_active",
    "session_age_seconds", "arrival_ts", "telemetry", "downtime", "alt_rail",
    "alt_rail_observed_healthy", "ambiguity_roll", "timing_noise_bp",
)


def build_observation(incident: dict[str, Any]) -> dict[str, Any]:
    """Project an incident onto what a recovery policy could actually know.

    The truth block and the outcome tape are excluded: the first is the answer
    key, the second is the sequence of coin flips. Both are resolved by the
    harness only after a policy has already committed to an attempt.
    """
    return {key: incident[key] for key in OBSERVABLE_KEYS}


# ---------------------------------------------------------------------------
# Outcome model
# ---------------------------------------------------------------------------


def retention_bp(elapsed_seconds: int, half_life_seconds: int) -> int:
    """Share of the payer still recoverable after elapsed_seconds, in basis points.

    Geometric decay evaluated in integers: exact halvings by shift, then a
    linear interpolation across the partial half-life. Floating-point would be
    marginally smoother and would make the corpus digest depend on the platform
    FPU, which is not a trade worth making for a curve this coarse.
    """
    if half_life_seconds <= 0:
        raise ValueError("generator: retention half-life must be positive")
    if elapsed_seconds <= 0:
        return 10_000
    halvings = elapsed_seconds // half_life_seconds
    if halvings >= MAX_HALVINGS:
        return 0
    remainder = elapsed_seconds - halvings * half_life_seconds
    value = 10_000 >> int(halvings)
    value -= (value * remainder) // (2 * half_life_seconds)
    return max(value, 0)


def _issuer_success_bp(incident: dict[str, Any], attempt: Attempt) -> int:
    """Probability the issuer would authorise this attempt, ignoring abandonment.

    The shape of this function is the whole experiment, so it is written out
    flat rather than parameterised: re-presenting an unchanged instrument to a
    permanently dead account is worth nothing, waiting past a real recovery
    instant is worth a great deal, and moving to a genuinely healthy rail
    sidesteps an issuer-scoped outage but does nothing about an empty account.
    """
    if (
        incident["is_recurring"]
        and not attempt.afa_obtained
        and incident["amount_paisa"] > afa_ceiling_paisa(incident["mandate_category"])
    ):
        # The additional-factor ceiling is enforced on the rail, not only by the
        # regulator: a mandate registered under it cannot be debited above it
        # without a fresh factor, and the issuer declines the presentment. A
        # model that paid out on such a debit and then charged a Rs 500 penalty
        # for it would be pricing a breach as profitable, which is an artifact
        # of the model rather than a fact about the market.
        return 0

    truth = incident["truth"]
    cls = truth["class"]
    if cls == CLASS_PERMANENT:
        return 0
    if cls == CLASS_STALE:
        if attempt.presentation in (P_NETWORK_TOKEN, P_FRESH_AUTH):
            return truth["refresh_bp"]
        return 0
    same_rail = attempt.rail == incident["rail"]
    if cls in (CLASS_OUTAGE, CLASS_TRANSIENT):
        if not same_rail:
            return truth["alt_rail_bp"]
        return truth["recovered_bp"] if attempt.at >= truth["recovery_ts"] else truth["floor_bp"]
    if cls == CLASS_FUNDS:
        # Money does not appear because the rail changed.
        return truth["recovered_bp"] if attempt.at >= truth["recovery_ts"] else truth["floor_bp"]
    if cls == CLASS_CUSTOMER:
        if attempt.in_session:
            return truth["recovered_bp"]
        if attempt.presentation == P_FRESH_AUTH:
            return truth["oob_auth_bp"]
        return truth["floor_bp"]
    return 0


def success_probability_bp(incident: dict[str, Any], attempt: Attempt) -> int:
    """Issuer authorisation probability discounted by the abandonment hazard.

    Recovery is a joint event: the issuer has to say yes and the payer has to
    still be there. Separating the two keeps the latency cost visible, which is
    the only reason a mechanism that recovers in seconds rather than hours is
    worth anything on this scorecard.
    """
    elapsed = attempt.at - incident["arrival_ts"]
    retained = retention_bp(elapsed, incident["truth"]["retention_half_life_seconds"])
    return _issuer_success_bp(incident, attempt) * retained // 10_000


def attempt_success(incident: dict[str, Any], attempt: Attempt, index: int) -> bool:
    """Resolve one attempt against the incident pre-drawn outcome tape.

    The tape is per-incident and indexed by attempt number, so every policy
    resolves its k-th attempt against the same uniform draw. That is the common
    random numbers construction: it removes Monte-Carlo noise from the
    comparison and is what makes the design genuinely paired rather than merely
    run on the same inputs.
    """
    if index < 0 or index >= len(incident["draws"]):
        raise IndexError(f"generator: attempt index {index} outside the pre-drawn outcome tape")
    return success_probability_bp(incident, attempt) > incident["draws"][index]


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------


def generate(count: int, seed: int) -> list[dict[str, Any]]:
    """Draw count incidents deterministically from seed."""
    if not isinstance(count, int) or isinstance(count, bool):
        raise TypeError("generator: incident count must be an int")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError("generator: seed must be an int")
    if count < 1 or count > MAX_INCIDENTS:
        raise ValueError(f"generator: incident count must be in [1, {MAX_INCIDENTS}], got {count}")
    if seed < 0 or seed > MAX_SEED:
        raise ValueError(f"generator: seed must be in [0, {MAX_SEED}], got {seed}")

    rng = np.random.default_rng(seed)
    outages = _generate_outages(rng, count)
    return [_generate_incident(rng, index, outages) for index in range(count)]


def canonical_json(value: Any) -> str:
    """Canonical form used everywhere a digest is taken.

    Sorted keys, no insignificant whitespace, ASCII-escaped. The ASCII
    constraint is not cosmetic: the Go attestation verifier re-marshals the same
    structure, and keeping every byte inside ASCII removes both Unicode escaping
    and Go HTML escaping as sources of cross-language disagreement.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def incidents_digest(incidents: list[dict[str, Any]]) -> str:
    """SHA-256 over the canonical corpus, including the latent truth.

    Digesting the truth as well as the observation is deliberate: it commits the
    run to a specific answer key, so a later edit that quietly made the
    incidents easier for one policy cannot reuse the published hash.
    """
    return hashlib.sha256(canonical_json(incidents).encode("utf-8")).hexdigest()
