"""The four recovery policies under test, plus the referee that scores them.

The comparison is only worth reading if the policies are judged by rules none
of them owns. Two things enforce that here:

* ``audit_violations`` is a single compliance referee applied identically to
  every policy. A policy declares what it did -- when it debited, whether it
  notified, whether it authenticated -- and the referee counts breaches. No
  policy self-reports its own violation count, so none can grade itself
  generously.
* Every policy is handed the same ``build_observation`` projection and resolves
  its k-th attempt against the same pre-drawn uniform. Same incidents, same
  coin flips, different decisions.

Where the baselines are deliberately weak, the weakness is the documented
weakness of that class of system rather than one invented to lose:

* ``blind_retry``  -- a fixed retry loop, the thing most merchants actually run.
* ``static_rules`` -- an error-code lookup table. Its failure mode is
  classification: ambiguous technical errors are a coin flip that a table
  resolves the same way every time, and refreshable declines look terminal to it.
* ``incumbent_smart_retry`` -- published smart-retry behaviour. It is a genuinely
  strong baseline and is given every card-network capability that is real:
  correct terminal-decline suppression, network-token account-updater refresh,
  and issuer-prior retry timing. It shares the mesh funding-recovery schedule
  outright, so no part of the gap is manufactured on that axis. What it does not
  have is in-session healing (there is no session to heal) and an India-specific
  compliance model.
* ``resilientmesh`` -- the system under test.
"""

from __future__ import annotations

from typing import Any, Callable

from generator import (
    AMBIGUOUS_FAILURE_CODES,
    P_FRESH_AUTH,
    P_NETWORK_TOKEN,
    P_UNCHANGED,
    REFRESHABLE_DECLINE_CODES,
    SESSION_TTL_SECONDS,
    SOFT_DECLINE_CODES,
    TERMINAL_DECLINE_CODES,
    Attempt,
    afa_ceiling_paisa,
    attempt_success,
    build_observation,
)

HOUR = 3600
DAY = 86400

# ---------------------------------------------------------------------------
# Compliance rules. These mirror the gatekeeper invariant set in
# internal/gatekeeper: RBI_MANDATE_COOLING, RBI_PRE_DEBIT_NOTICE,
# RBI_AFA_CEILING and MANDATE_CYCLE_CAP.
# ---------------------------------------------------------------------------

MANDATE_COOLING_SECONDS = 86400
MANDATE_CYCLE_CAP = 3
GLOBAL_MAX_ATTEMPTS = 3

# Hard ceiling on the simulation loop. A policy bug that never returns None must
# terminate the run rather than spin; it also bounds the outcome tape lookup.
MAX_ATTEMPTS_HARD = 8

# Codes whose recovery needs the customer back, not a different rail.
CUSTOMER_ACTION_CODES = frozenset({
    "invalid_otp", "incorrect_otp", "authentication_failed", "upi_collect_expired",
})
FUNDS_CODES = frozenset({"insufficient_funds", "mandate_not_active"})

# ---------------------------------------------------------------------------
# Policy tuning. Every knob is an integer and every one of them is attested, so
# a reviewer can see the exact configuration that produced a published number.
# ---------------------------------------------------------------------------

BLIND_RETRY_ATTEMPTS = 3
BLIND_RETRY_DELAY_SECONDS = 30

STATIC_RULES_AMBIGUOUS_ATTEMPTS = 3
STATIC_RULES_SOFT_ATTEMPTS = 2
STATIC_RULES_AMBIGUOUS_DELAY_SECONDS = 600
STATIC_RULES_SOFT_DELAY_SECONDS = 300
# Share of ambiguous technical errors the table resolves to "permanent, stop".
# A lookup table has one answer per code and roughly a third of real ambiguous
# declines are genuinely unrecoverable, so a table tuned to stop is wrong
# exactly this often on the ones that were recoverable.
STATIC_RULES_MISCLASSIFY_BP = 3500

INCUMBENT_MAX_ATTEMPTS = 3
INCUMBENT_REFRESH_ATTEMPTS = 2
INCUMBENT_REFRESH_DELAY_SECONDS = 120
INCUMBENT_DEFAULT_SCHEDULE = (600, 3600, 21600)
# Prior on issuer recovery, scaled per incident. This is the honest model of a
# statistically timed retry: unbiased on average, wrong on any given outage,
# because nothing in it observes the actual resolution.
INCUMBENT_OUTAGE_PRIOR_SECONDS = 5400
INCUMBENT_MIN_WAIT_SECONDS = 600
INCUMBENT_MAX_WAIT_SECONDS = 12 * HOUR

# Shared between the incumbent and the mesh so that funding recovery, which
# neither system observes directly, contributes nothing to the measured gap.
FUNDS_RETRY_SCHEDULE = (6 * HOUR, 24 * HOUR, 48 * HOUR)

MESH_MAX_ATTEMPTS = GLOBAL_MAX_ATTEMPTS
MESH_REFRESH_ATTEMPTS = 2
MESH_REFRESH_DELAY_SECONDS = 120
MESH_BACKOFF_SCHEDULE = (60, 600, 3600)
MESH_DEGRADED_SCHEDULE = (300, 1800, 7200)
# Upper bound on a parked command. The downtime resolution is the mechanism; the
# backoff is only the deadline for when no resolution ever arrives.
MESH_DOWNTIME_UPPER_BOUND = (2 * HOUR, 6 * HOUR, 24 * HOUR)
# Delay between the published resolution and the released retry. Firing on the
# same second the issuer declares itself healthy lands in the recovery stampede.
DOWNTIME_RELEASE_LAG_SECONDS = 20

POLICY_CONFIG: dict[str, Any] = {
    "blind_retry": {
        "attempts": BLIND_RETRY_ATTEMPTS,
        "delay_seconds": BLIND_RETRY_DELAY_SECONDS,
        "compliance_model": "none",
    },
    "static_rules": {
        "ambiguous_attempts": STATIC_RULES_AMBIGUOUS_ATTEMPTS,
        "ambiguous_delay_seconds": STATIC_RULES_AMBIGUOUS_DELAY_SECONDS,
        "soft_attempts": STATIC_RULES_SOFT_ATTEMPTS,
        "soft_delay_seconds": STATIC_RULES_SOFT_DELAY_SECONDS,
        "misclassify_ambiguous_bp": STATIC_RULES_MISCLASSIFY_BP,
        "compliance_model": "cooling_window_only",
    },
    "incumbent_smart_retry": {
        "max_attempts": INCUMBENT_MAX_ATTEMPTS,
        "refresh_attempts": INCUMBENT_REFRESH_ATTEMPTS,
        "refresh_delay_seconds": INCUMBENT_REFRESH_DELAY_SECONDS,
        "default_schedule_seconds": list(INCUMBENT_DEFAULT_SCHEDULE),
        "outage_prior_seconds": INCUMBENT_OUTAGE_PRIOR_SECONDS,
        "min_wait_seconds": INCUMBENT_MIN_WAIT_SECONDS,
        "max_wait_seconds": INCUMBENT_MAX_WAIT_SECONDS,
        "funds_schedule_seconds": list(FUNDS_RETRY_SCHEDULE),
        "compliance_model": "cooling_window_only",
    },
    "resilientmesh": {
        "max_attempts": MESH_MAX_ATTEMPTS,
        "refresh_attempts": MESH_REFRESH_ATTEMPTS,
        "refresh_delay_seconds": MESH_REFRESH_DELAY_SECONDS,
        "backoff_schedule_seconds": list(MESH_BACKOFF_SCHEDULE),
        "degraded_schedule_seconds": list(MESH_DEGRADED_SCHEDULE),
        "downtime_upper_bound_seconds": list(MESH_DOWNTIME_UPPER_BOUND),
        "downtime_release_lag_seconds": DOWNTIME_RELEASE_LAG_SECONDS,
        "funds_schedule_seconds": list(FUNDS_RETRY_SCHEDULE),
        "compliance_model": "rbi_full",
    },
    "shared": {
        "mandate_cooling_seconds": MANDATE_COOLING_SECONDS,
        "mandate_cycle_cap": MANDATE_CYCLE_CAP,
        "afa_ceiling_general_paisa": afa_ceiling_paisa("general"),
        "afa_ceiling_elevated_paisa": afa_ceiling_paisa("insurance"),
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "max_attempts_hard": MAX_ATTEMPTS_HARD,
    },
}


# ---------------------------------------------------------------------------
# The referee
# ---------------------------------------------------------------------------


def audit_violations(observation: dict[str, Any], attempts: list[Attempt]) -> int:
    """Count RBI e-mandate breaches in a policy attempt sequence.

    One implementation scores all four policies. Each breach is a distinct
    regulatory failure and is counted separately, because they are separately
    actionable: a debit that was too soon, a debit with no pre-debit notice, a
    debit above the additional-factor ceiling, and a debit past the per-cycle
    ceiling are four different findings even when they land on one attempt.

    Non-recurring payments carry no mandate obligations and are never charged a
    violation, which is why the metric does not simply track retry volume.
    """
    if not observation["is_recurring"] or not attempts:
        return 0

    violations = 0
    ceiling = afa_ceiling_paisa(observation["mandate_category"])
    above_ceiling = observation["amount_paisa"] > ceiling
    # The original failed debit is the previous attempt in the cycle: the
    # cooling window runs from it, not from the moment the policy woke up.
    previous_at = observation["arrival_ts"]

    for attempt in attempts:
        if attempt.at - previous_at < MANDATE_COOLING_SECONDS:
            violations += 1
        if not attempt.pre_debit_notified:
            violations += 1
        if above_ceiling and not attempt.afa_obtained:
            violations += 1
        previous_at = attempt.at

    in_cycle = observation["attempts_in_cycle_before"] + len(attempts)
    if in_cycle > MANDATE_CYCLE_CAP:
        violations += in_cycle - MANDATE_CYCLE_CAP
    return violations


# ---------------------------------------------------------------------------
# Policies. Each is a planner: given the observation and the attempts made so
# far, return the next attempt or None to stop.
# ---------------------------------------------------------------------------


def _previous_at(observation: dict[str, Any], history: tuple[Attempt, ...]) -> int:
    return history[-1].at if history else observation["arrival_ts"]


def plan_blind_retry(observation: dict[str, Any], history: tuple[Attempt, ...]) -> Attempt | None:
    """Fixed retry loop: three attempts, thirty seconds apart, no model at all.

    It does not read the error taxonomy, so it spends gateway fees on declines
    that cannot succeed, and it has no notion of a mandate, so every recurring
    incident it touches breaches the cooling window and the notice obligation.
    """
    if len(history) >= BLIND_RETRY_ATTEMPTS:
        return None
    return Attempt(
        at=_previous_at(observation, history) + BLIND_RETRY_DELAY_SECONDS,
        rail=observation["rail"],
        presentation=P_UNCHANGED,
        in_session=False,
        pre_debit_notified=False,
        afa_obtained=False,
        comms_messages=0,
    )


def plan_static_rules(observation: dict[str, Any], history: tuple[Attempt, ...]) -> Attempt | None:
    """Error-code lookup table, the standard rules-engine shape.

    It correctly suppresses terminal declines, which is a real improvement over
    a blind loop. Its two failures are the ones a table cannot avoid: a
    refreshable decline reads as terminal because the code says the card is
    gone, and an ambiguous technical error gets one fixed answer where the truth
    varies per incident. It knows the 24-hour cooling window because that fits
    in a table; it has no pre-debit notification path and no ceiling check
    because those are not code lookups.
    """
    code = observation["error_code"]
    if code in TERMINAL_DECLINE_CODES:
        return None
    if code in REFRESHABLE_DECLINE_CODES:
        # The documented misclassification: an expired card is filed as dead.
        return None
    if code in AMBIGUOUS_FAILURE_CODES and observation["ambiguity_roll"] < STATIC_RULES_MISCLASSIFY_BP:
        return None

    soft = code in SOFT_DECLINE_CODES
    limit = STATIC_RULES_SOFT_ATTEMPTS if soft else STATIC_RULES_AMBIGUOUS_ATTEMPTS
    if len(history) >= limit:
        return None

    delay = STATIC_RULES_SOFT_DELAY_SECONDS if soft else STATIC_RULES_AMBIGUOUS_DELAY_SECONDS
    if observation["is_recurring"]:
        delay = max(delay, MANDATE_COOLING_SECONDS)
    return Attempt(
        at=_previous_at(observation, history) + delay,
        rail=observation["rail"],
        presentation=P_UNCHANGED,
        in_session=False,
        pre_debit_notified=False,
        afa_obtained=False,
        comms_messages=0,
    )


def _estimated_outage_wait(observation: dict[str, Any], attempt_index: int) -> int:
    """Statistically timed wait for an issuer believed to be degraded.

    The estimate is a prior scaled by a per-incident term in [0.70, 1.30] and
    doubled on each successive attempt. It is centred on the right answer and
    wrong on any particular outage, which is exactly the cost of estimating a
    recovery that is in fact published.
    """
    scale = 7000 + (observation["timing_noise_bp"] * 6000) // 10_000
    wait = (INCUMBENT_OUTAGE_PRIOR_SECONDS * scale) // 10_000
    wait = wait * (2 ** attempt_index)
    return min(max(wait, INCUMBENT_MIN_WAIT_SECONDS), INCUMBENT_MAX_WAIT_SECONDS)


def plan_incumbent_smart_retry(
    observation: dict[str, Any], history: tuple[Attempt, ...]
) -> Attempt | None:
    """Published smart-retry behaviour: card-network centric, ML-timed.

    It suppresses terminal declines, runs an account-updater refresh through a
    network token on refreshable ones, and times retries from an issuer prior
    rather than a fixed table. It never morphs a live session because it has no
    session, and it carries no RBI model, so a mandate debit goes out without a
    pre-debit notice, without an additional-factor check, and without a
    per-cycle ceiling.
    """
    code = observation["error_code"]
    if code in TERMINAL_DECLINE_CODES:
        return None

    index = len(history)
    presentation = P_UNCHANGED

    if code in REFRESHABLE_DECLINE_CODES:
        if index >= INCUMBENT_REFRESH_ATTEMPTS:
            return None
        presentation = P_NETWORK_TOKEN
        delay = INCUMBENT_REFRESH_DELAY_SECONDS
    else:
        if index >= INCUMBENT_MAX_ATTEMPTS:
            return None
        if code in FUNDS_CODES:
            delay = FUNDS_RETRY_SCHEDULE[index]
        elif observation["telemetry"]["degraded"]:
            delay = _estimated_outage_wait(observation, index)
        else:
            delay = INCUMBENT_DEFAULT_SCHEDULE[index]

    if observation["is_recurring"]:
        # A card-network retry schedule for a recurring debit runs in days, so
        # the cooling window happens to be satisfied. Nothing else is.
        delay = max(delay, MANDATE_COOLING_SECONDS)

    return Attempt(
        at=_previous_at(observation, history) + delay,
        rail=observation["rail"],
        presentation=presentation,
        in_session=False,
        pre_debit_notified=False,
        afa_obtained=False,
        comms_messages=0,
    )


def plan_resilientmesh(observation: dict[str, Any], history: tuple[Attempt, ...]) -> Attempt | None:
    """ResilientMesh: in-session healing, published-resolution release, RBI invariants.

    Ordered the way the gatekeeper orders its invariants, because that ordering
    is the specification: the compliance vetoes run before any scheduling
    arithmetic, so a debit that must not happen is never scheduled and then
    un-scheduled.

    The downtime release is not foreknowledge. The command is parked against an
    issuer key and released when the resolution notice arrives; the computed
    backoff is the deadline for the case where no notice ever comes. That is a
    reaction to a published event, and it only exists here because in this
    ecosystem issuer recovery is announced rather than guessed.
    """
    code = observation["error_code"]
    if code in TERMINAL_DECLINE_CODES:
        return None

    index = len(history)
    if index >= MESH_MAX_ATTEMPTS:
        return None

    recurring = observation["is_recurring"]
    if recurring:
        # RBI_AFA_CEILING. Above the applicable ceiling the debit needs a fresh
        # additional factor, which no automatic retry can supply. Abstaining
        # forfeits the recovery; re-presenting would be a breach.
        if observation["amount_paisa"] > afa_ceiling_paisa(observation["mandate_category"]):
            return None
        # MANDATE_CYCLE_CAP, counted against attempts already made this cycle.
        if observation["attempts_in_cycle_before"] + index >= MANDATE_CYCLE_CAP:
            return None

    previous_at = _previous_at(observation, history)
    rail = observation["rail"]
    presentation = P_UNCHANGED
    in_session = False
    comms = 0

    if code in REFRESHABLE_DECLINE_CODES:
        if index >= MESH_REFRESH_ATTEMPTS:
            return None
        presentation = P_NETWORK_TOKEN
        attempt_at = previous_at + MESH_REFRESH_DELAY_SECONDS
    else:
        elapsed = previous_at - observation["arrival_ts"]
        # One in-session action per incident. After a morph the alternate rail
        # is the rail that just failed, and RAIL_ALLOWLIST forbids targeting it;
        # after a declined in-page prompt, prompting the same customer again in
        # the same session is asking a question already answered. Either way the
        # incident falls through to the async path.
        healed_in_session = any(attempt.in_session for attempt in history)
        session_live = (
            observation["session_active"]
            and not recurring
            and not healed_in_session
            and observation["session_age_seconds"] + elapsed < SESSION_TTL_SECONDS
        )
        # Only ambiguous or telemetry-confirmed issuer trouble justifies moving
        # rails. Morphing a funding failure onto another rail spends a fee and a
        # friction prompt to ask a different institution for money that is not
        # there.
        issuer_suspect = observation["telemetry"]["degraded"] or code in AMBIGUOUS_FAILURE_CODES

        if session_live and issuer_suspect and observation["alt_rail_observed_healthy"]:
            rail = observation["alt_rail"]
            in_session = True
            attempt_at = previous_at
        elif session_live and code in CUSTOMER_ACTION_CODES:
            presentation = P_FRESH_AUTH
            in_session = True
            attempt_at = previous_at
        elif code in FUNDS_CODES:
            attempt_at = previous_at + FUNDS_RETRY_SCHEDULE[index]
        else:
            if code in CUSTOMER_ACTION_CODES:
                # Out of session the customer has to be brought back, which
                # costs a message and converts worse than an in-page prompt.
                presentation = P_FRESH_AUTH
                comms += 1
            schedule = MESH_DEGRADED_SCHEDULE if issuer_suspect else MESH_BACKOFF_SCHEDULE
            attempt_at = previous_at + schedule[index]

            downtime = observation["downtime"]
            if (
                downtime is not None
                and downtime["matches_issuer"]
                and downtime["status"] == "started"
                and downtime["end"] is not None
            ):
                release_at = downtime["end"] + DOWNTIME_RELEASE_LAG_SECONDS
                deadline = previous_at + MESH_DOWNTIME_UPPER_BOUND[index]
                attempt_at = max(previous_at, min(release_at, deadline))

    pre_debit = False
    if recurring:
        # RBI_MANDATE_COOLING and RBI_PRE_DEBIT_NOTICE. The notice is a real
        # message with a real cost; paying it is what compliance costs.
        pre_debit = True
        comms += 1
        attempt_at = max(attempt_at, previous_at + MANDATE_COOLING_SECONDS)

    return Attempt(
        at=attempt_at,
        rail=rail,
        presentation=presentation,
        in_session=in_session,
        pre_debit_notified=pre_debit,
        # Never true, and correctly so: the AFA veto above means this policy
        # only ever reaches a debit at or below the ceiling, where no fresh
        # additional factor is required. Claiming one would be a lie to the
        # referee.
        afa_obtained=False,
        comms_messages=comms,
    )


Planner = Callable[[dict[str, Any], "tuple[Attempt, ...]"], "Attempt | None"]

# Ordered so the output table always reads weakest to strongest.
POLICIES: tuple[tuple[str, Planner], ...] = (
    ("blind_retry", plan_blind_retry),
    ("static_rules", plan_static_rules),
    ("incumbent_smart_retry", plan_incumbent_smart_retry),
    ("resilientmesh", plan_resilientmesh),
)

POLICY_NAMES = tuple(name for name, _ in POLICIES)
TREATMENT_POLICY = "resilientmesh"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class PolicyOutcome:
    """What one policy did to one incident, and what it was worth in paisa.

    Every field is an int. Net recovered contribution value is assembled here
    and nowhere else, so there is exactly one place where the accounting could
    be wrong.
    """

    __slots__ = (
        "recovered", "recovered_paisa", "retries", "comms_messages", "morphs",
        "violations", "nrcv_paisa", "attempts",
    )

    def __init__(
        self,
        recovered: bool,
        recovered_paisa: int,
        retries: int,
        comms_messages: int,
        morphs: int,
        violations: int,
        nrcv_paisa: int,
        attempts: tuple[Attempt, ...],
    ) -> None:
        self.recovered = recovered
        self.recovered_paisa = recovered_paisa
        self.retries = retries
        self.comms_messages = comms_messages
        self.morphs = morphs
        self.violations = violations
        self.nrcv_paisa = nrcv_paisa
        self.attempts = attempts


def nrcv_paisa(
    recovered_paisa: int,
    retries: int,
    comms_messages: int,
    violations: int,
    morphs: int,
    costs: dict[str, int],
) -> int:
    """Net recovered contribution value, in integer paisa.

    Recovered revenue less what it cost to go and get it: gateway fees on every
    outbound attempt, out-of-band messages, regulatory penalties, and the
    friction of interrupting a live checkout. Rupees exist only in the
    rendering layer; nothing downstream of this function divides by 100.
    """
    return (
        recovered_paisa
        - retries * costs["gateway_fee_per_attempt_paisa"]
        - comms_messages * costs["comms_cost_per_message_paisa"]
        - violations * costs["compliance_penalty_paisa"]
        - morphs * costs["session_friction_paisa"]
    )


def simulate(incident: dict[str, Any], planner: Planner, costs: dict[str, int]) -> PolicyOutcome:
    """Run one policy against one incident and score the result."""
    observation = build_observation(incident)
    history: list[Attempt] = []
    recovered = False

    for index in range(MAX_ATTEMPTS_HARD):
        nxt = planner(observation, tuple(history))
        if nxt is None:
            break
        floor = _previous_at(observation, tuple(history))
        if nxt.at < floor:
            raise ValueError(
                f"policy scheduled an attempt at {nxt.at}, before the previous event at {floor}"
            )
        history.append(nxt)
        if attempt_success(incident, nxt, index):
            recovered = True
            break

    retries = len(history)
    comms = sum(attempt.comms_messages for attempt in history)
    morphs = sum(1 for attempt in history if attempt.in_session and attempt.rail != observation["rail"])
    violations = audit_violations(observation, history)
    recovered_paisa = observation["amount_paisa"] if recovered else 0

    return PolicyOutcome(
        recovered=recovered,
        recovered_paisa=recovered_paisa,
        retries=retries,
        comms_messages=comms,
        morphs=morphs,
        violations=violations,
        nrcv_paisa=nrcv_paisa(recovered_paisa, retries, comms, violations, morphs, costs),
        attempts=tuple(history),
    )
