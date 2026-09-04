#!/usr/bin/env python3
"""Poisson-burst outage injection against a running ResilientMesh stack.

Why this exists
---------------
A recovery system is only interesting under failure, and a demo is only
trustworthy if the failure was scripted rather than lucky. This injector draws
every outage, every severity and every failure burst from one seeded generator,
prints the whole schedule *before* it runs, and writes the same schedule to
JSON. The narration and the system therefore describe the same events, and a
reviewer can re-run the identical incident timeline from the seed alone.

Model
-----
Outage bursts arrive as a Poisson process of ``--rate`` bursts per minute over
``--duration`` seconds. Profiles with a non-constant intensity (``mandate-batch``
models the two nightly recurring-debit submission windows) are drawn as a
*non-homogeneous* Poisson process by Lewis-Shedler thinning against the profile
peak, which keeps the arrivals a genuine Poisson process rather than a jittered
schedule dressed up as one.

Each burst produces three kinds of event:

  downtime.start    a Razorpay downtime notice opens on one instrument
  failure.burst     N payments fail on that instrument with a drawn error code
  downtime.resolve  the notice closes

The resolution event is not decoration: commands parked with
``ReleaseOnDowntimeResolution`` are released by it, so a run without
resolutions never exercises the release path.

Control surface
---------------
Events are POSTed to the simulator's chaos control API, rooted at
``--control-prefix`` (default ``/v1/chaos``):

  POST {prefix}/downtimes              body: a Razorpay DowntimeEntity
  POST {prefix}/downtimes/{id}/resolve body: {"id", "end"}
  POST {prefix}/failures               body: {"telemetry_key", "method",
                                              "error_code", "count",
                                              "recurring", "seed", "burst"}

The downtime body is the exact schema ``domain.DowntimeEntity`` marshals, so
the simulator can hand it back on ``GET /v1/downtimes`` unchanged.

Safety
------
Chaos aimed at the wrong host is the only way this script can do damage, so it
fails closed: non-loopback targets are refused unless ``--allow-remote`` is
given explicitly, redirects are never followed (a redirect would carry the
bearer token to another host), the credential is read from the environment
rather than a flag so it cannot leak into a process listing, and the plan is
bounded before a single request is sent.

Dependencies: Python 3.12 standard library plus numpy. No requests, no aiohttp.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import numpy as np

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

# Every one of these is a fail-closed limit rather than a preference. An
# injector that can be asked for an unbounded plan is a load generator pointed
# at your own stack by accident.
MAX_SEED = 2**32 - 1
MAX_RATE_PER_MIN = 120.0
MAX_DURATION_S = 24 * 3600
MAX_EVENTS = 2000
MAX_FAILURES_PER_BURST = 200
MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_S = 5.0

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


# ---------------------------------------------------------------------------
# Instruments and profiles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Instrument:
    """One issuer as both a Razorpay downtime instrument and a telemetry key."""

    method: str
    instrument: dict[str, str]
    # Error codes this instrument realistically emits, drawn uniformly. All of
    # them are in domain.AmbiguousFailureCodes: injecting an unambiguous code
    # would exercise the taxonomy short-circuit, not the recovery path.
    codes: tuple[str, ...]

    @property
    def telemetry_key(self) -> str:
        return telemetry_key(self.method, self.instrument)


def telemetry_key(method: str, instrument: dict[str, str]) -> str:
    """Mirror of domain.DowntimeEntity.TelemetryKey.

    Kept in step deliberately: if the injector and the mesh disagree about what
    key an outage lands on, the downtime signal never joins the failure
    counters and the whole run silently proves nothing.
    """
    m = method.strip().lower()
    if m == "upi":
        handle = instrument.get("vpa_handle") or instrument.get("psp")
        return f"upi:{handle.lower()}" if handle else "upi:unknown"
    if m == "wallet":
        issuer = instrument.get("issuer")
        return f"wallet:{issuer.lower()}" if issuer else "wallet:unknown"
    issuer = instrument.get("issuer") or instrument.get("bank")
    return f"{m}:{issuer.upper()}" if issuer else f"{m}:unknown"


CARD_ISSUERS = (
    Instrument("card", {"issuer": "HDFC", "network": "VISA", "card_type": "credit"},
               ("bank_technical_error", "issuer_down", "gateway_technical_error")),
    Instrument("card", {"issuer": "ICICI", "network": "MC", "card_type": "debit"},
               ("bank_technical_error", "payment_timed_out", "gateway_technical_error")),
    Instrument("card", {"issuer": "SBIN", "network": "RUPAY", "card_type": "debit"},
               ("issuer_down", "server_error", "bank_technical_error")),
)

NETBANKING_ISSUERS = (
    Instrument("netbanking", {"issuer": "HDFC", "bank": "HDFC"},
               ("bank_technical_error", "server_error", "payment_timed_out")),
    Instrument("netbanking", {"issuer": "SBIN", "bank": "SBIN"},
               ("server_error", "bank_technical_error")),
    Instrument("netbanking", {"issuer": "UTIB", "bank": "UTIB"},
               ("bank_technical_error", "issuer_down")),
)

UPI_HANDLES = (
    Instrument("upi", {"vpa_handle": "okhdfcbank", "psp": "HDFC"},
               ("upi_psp_error", "payment_timed_out", "payment_pending")),
    Instrument("upi", {"vpa_handle": "ybl", "psp": "YESB"},
               ("upi_psp_error", "gateway_technical_error", "payment_pending")),
    Instrument("upi", {"vpa_handle": "paytm", "psp": "PYTM"},
               ("upi_psp_error", "payment_timed_out")),
    Instrument("upi", {"vpa_handle": "okicici", "psp": "ICIC"},
               ("gateway_technical_error", "upi_psp_error")),
)

WALLETS = (
    Instrument("wallet", {"issuer": "paytm"}, ("gateway_error", "payment_timed_out")),
    Instrument("wallet", {"issuer": "phonepe"}, ("gateway_error", "server_error")),
)


def flat_intensity(_t: float, _duration: float) -> float:
    return 1.0


def batch_window_intensity(t: float, duration: float) -> float:
    """Two submission peaks, the shape a recurring-debit batch actually has.

    Mandate debits are not sprayed uniformly across the day: a processor
    submits them in windows, so failures arrive clustered. Injecting them
    uniformly would understate exactly the queue pressure the mandate path is
    supposed to survive.
    """
    baseline = 0.15
    peak = 0.0
    for centre, width in ((0.25, 0.06), (0.65, 0.08)):
        x = (t / duration - centre) / width
        peak += float(np.exp(-0.5 * x * x))
    return min(1.0, baseline + peak)


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    instruments: tuple[Instrument, ...]
    severity_weights: tuple[float, float, float]  # high, medium, low
    outage_median_s: float
    outage_sigma: float
    outage_min_s: int
    outage_max_s: int
    failures_lambda: float
    scheduled_probability: float
    recurring_probability: float
    intensity: Callable[[float, float], float] = flat_intensity


PROFILES: dict[str, Profile] = {
    "issuer-outage": Profile(
        name="issuer-outage",
        description="One bank switch at a time falls over hard: long, high-severity, card and netbanking.",
        instruments=CARD_ISSUERS + NETBANKING_ISSUERS,
        severity_weights=(0.70, 0.25, 0.05),
        outage_median_s=900.0,
        outage_sigma=0.45,
        outage_min_s=240,
        outage_max_s=3600,
        failures_lambda=14.0,
        scheduled_probability=0.10,
        recurring_probability=0.15,
    ),
    "psp-degradation": Profile(
        name="psp-degradation",
        description="UPI PSP handles brown out: frequent, shorter, mostly medium severity.",
        instruments=UPI_HANDLES,
        severity_weights=(0.25, 0.55, 0.20),
        outage_median_s=300.0,
        outage_sigma=0.55,
        outage_min_s=90,
        outage_max_s=1200,
        failures_lambda=22.0,
        scheduled_probability=0.05,
        recurring_probability=0.10,
    ),
    "mixed": Profile(
        name="mixed",
        description="The realistic ecosystem: cards, netbanking, UPI and wallets failing independently.",
        instruments=CARD_ISSUERS + NETBANKING_ISSUERS + UPI_HANDLES + WALLETS,
        severity_weights=(0.40, 0.40, 0.20),
        outage_median_s=600.0,
        outage_sigma=0.60,
        outage_min_s=120,
        outage_max_s=2700,
        failures_lambda=18.0,
        scheduled_probability=0.20,
        recurring_probability=0.25,
    ),
    "mandate-batch": Profile(
        name="mandate-batch",
        description="Recurring-debit submission windows: clustered bursts, mostly recurring, netbanking and card heavy.",
        instruments=NETBANKING_ISSUERS + CARD_ISSUERS,
        severity_weights=(0.35, 0.45, 0.20),
        outage_median_s=1200.0,
        outage_sigma=0.40,
        outage_min_s=300,
        outage_max_s=5400,
        failures_lambda=30.0,
        scheduled_probability=0.35,
        recurring_probability=0.90,
        intensity=batch_window_intensity,
    ),
}

SEVERITIES = ("high", "medium", "low")


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """One scheduled injection. Ordering is by (offset, seq) so the plan is a
    total order even when two events land on the same virtual instant."""

    seq: int
    offset_s: float
    kind: str
    burst: int
    telemetry_key: str
    method: str
    downtime_id: str
    detail: dict[str, Any] = field(default_factory=dict)
    status: str = "planned"
    http_status: int | None = None
    error: str | None = None

    def row(self) -> str:
        mm, ss = divmod(int(self.offset_s), 60)
        return f"  {mm:02d}:{ss:02d}  {self.kind:<18}  {self.telemetry_key:<22}  {self.summary()}"

    def summary(self) -> str:
        if self.kind == "downtime.start":
            d = self.detail
            sched = " scheduled" if d.get("scheduled") else ""
            return f"{d['severity']}-severity{sched} for {int(d['duration_s'])}s  [{self.downtime_id}]"
        if self.kind == "downtime.resolve":
            return f"notice closes  [{self.downtime_id}]"
        d = self.detail
        kind = "recurring" if d.get("recurring") else "one-off"
        return f"{d['count']} x {d['error_code']} ({kind})"

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "seq": self.seq,
            "offset_s": round(self.offset_s, 3),
            "kind": self.kind,
            "burst": self.burst,
            "telemetry_key": self.telemetry_key,
            "method": self.method,
            "downtime_id": self.downtime_id,
            "detail": self.detail,
            "status": self.status,
        }
        if self.http_status is not None:
            out["http_status"] = self.http_status
        if self.error is not None:
            out["error"] = self.error
        return out


def outage_bounds(profile: Profile, duration_s: float) -> tuple[int, int]:
    """Shortest and longest outage this run will draw.

    A run shorter than a typical outage emits no ``downtime.resolve`` at all,
    so the release-on-resolution path goes untested in exactly the short runs
    used for demos and CI. Both bounds are therefore pulled under 40% of the
    horizon, which guarantees notices close inside the window. On a run long
    enough for the profile's own range to fit, the cap is above that range and
    nothing is changed.
    """
    hi = min(profile.outage_max_s, max(30, int(duration_s * 0.4)))
    lo = profile.outage_min_s
    if lo > hi:
        # Only move the floor when the profile's own floor no longer fits;
        # otherwise a long run would silently get shorter outages than the
        # profile describes.
        lo = max(15, hi // 3)
    return lo, hi


def arrival_times(rng: np.random.Generator, profile: Profile, rate_per_min: float,
                  duration_s: float, max_bursts: int) -> list[float]:
    """Draw burst arrivals as a (possibly non-homogeneous) Poisson process.

    Thinning is what keeps ``mandate-batch`` honest. Sampling a "clustered"
    schedule by hand would produce arrivals whose statistics nobody can state;
    accepting homogeneous arrivals with probability lambda(t)/lambda_peak
    produces a process with a known intensity function.
    """
    peak_rate = rate_per_min / 60.0
    times: list[float] = []
    t = 0.0
    while True:
        gap = float(rng.exponential(1.0 / peak_rate))
        t += gap
        if t >= duration_s:
            break
        if profile.intensity(t, duration_s) >= float(rng.random()):
            times.append(t)
            if len(times) >= max_bursts:
                break
    return times


def build_plan(rng: np.random.Generator, profile: Profile, rate_per_min: float,
               duration_s: float, max_events: int) -> list[Event]:
    """Expand burst arrivals into the concrete event list.

    Every draw happens here, in a fixed order, before any I/O. That is what
    makes ``--dry-run`` and a live run describe the same timeline, and it is
    why a failed request cannot perturb the schedule of everything after it.
    """
    # Three events per burst, so bound the bursts by the event budget.
    max_bursts = max(1, max_events // 3)
    arrivals = arrival_times(rng, profile, rate_per_min, duration_s, max_bursts)

    outage_lo, outage_hi = outage_bounds(profile, duration_s)

    events: list[Event] = []
    seq = 0
    for burst, start in enumerate(arrivals, start=1):
        inst = profile.instruments[int(rng.integers(len(profile.instruments)))]
        severity = SEVERITIES[int(rng.choice(len(SEVERITIES), p=profile.severity_weights))]
        outage_s = int(np.clip(
            rng.lognormal(mean=float(np.log(profile.outage_median_s)), sigma=profile.outage_sigma),
            outage_lo, outage_hi))
        scheduled = bool(rng.random() < profile.scheduled_probability)
        recurring = bool(rng.random() < profile.recurring_probability)
        code = inst.codes[int(rng.integers(len(inst.codes)))]
        count = int(np.clip(rng.poisson(profile.failures_lambda), 1, MAX_FAILURES_PER_BURST))
        # Failures land shortly after the notice opens rather than exactly with
        # it: in production the notice trails the first failures, and a system
        # that only works when they are simultaneous is not being tested.
        failure_offset = float(rng.uniform(1.0, 8.0))

        downtime_id = f"down_{profile.name[:4]}{burst:03d}"
        key = inst.telemetry_key

        seq += 1
        events.append(Event(
            seq=seq, offset_s=start, kind="downtime.start", burst=burst,
            telemetry_key=key, method=inst.method, downtime_id=downtime_id,
            detail={
                "severity": severity,
                "scheduled": scheduled,
                "duration_s": outage_s,
                "instrument": dict(inst.instrument),
            },
        ))

        seq += 1
        events.append(Event(
            seq=seq, offset_s=start + failure_offset, kind="failure.burst", burst=burst,
            telemetry_key=key, method=inst.method, downtime_id=downtime_id,
            detail={"error_code": code, "count": count, "recurring": recurring},
        ))

        resolve_at = start + outage_s
        if resolve_at <= duration_s:
            seq += 1
            events.append(Event(
                seq=seq, offset_s=resolve_at, kind="downtime.resolve", burst=burst,
                telemetry_key=key, method=inst.method, downtime_id=downtime_id,
                detail={},
            ))

    events.sort(key=lambda e: (e.offset_s, e.seq))
    return events


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect.

    A control API has no reason to redirect, and following one would resend the
    bearer token to whatever host the response named. Failing the request is
    strictly safer than discovering that later.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise urllib.error.HTTPError(
            req.full_url, code, f"refusing redirect to {newurl}", headers, fp)


class Injector:
    """Posts events to the control API. Holds no state beyond the opener."""

    def __init__(self, target: str, prefix: str, timeout: float, token: str | None) -> None:
        self.target = target.rstrip("/")
        self.prefix = "/" + prefix.strip("/")
        self.timeout = timeout
        self._token = token
        self._opener = urllib.request.build_opener(NoRedirect)

    def _post(self, path: str, body: dict[str, Any]) -> tuple[int, str]:
        url = f"{self.target}{self.prefix}{path}"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "resilientmesh-chaos/1")
        if self._token:
            req.add_header("Authorization", f"Bearer {self._token}")
        with self._opener.open(req, timeout=self.timeout) as resp:
            payload = resp.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
            return int(resp.status), payload

    def send(self, ev: Event, wall_now: int) -> None:
        """Deliver one event, recording the outcome on the event itself.

        Failures are recorded and the run continues: the whole point of the
        injector is to exercise a system that is falling over, and aborting the
        schedule on the first refused request would make the timeline a lie.
        """
        try:
            if ev.kind == "downtime.start":
                status, _ = self._post("/downtimes", downtime_entity(ev, wall_now))
            elif ev.kind == "downtime.resolve":
                status, _ = self._post(
                    f"/downtimes/{urllib.parse.quote(ev.downtime_id, safe='')}/resolve",
                    {"id": ev.downtime_id, "end": wall_now})
            else:
                status, _ = self._post("/failures", {
                    "telemetry_key": ev.telemetry_key,
                    "method": ev.method,
                    "error_code": ev.detail["error_code"],
                    "count": ev.detail["count"],
                    "recurring": ev.detail["recurring"],
                    "downtime_id": ev.downtime_id,
                    "burst": ev.burst,
                })
        except urllib.error.HTTPError as exc:
            ev.status, ev.http_status = "rejected", int(exc.code)
            ev.error = f"HTTP {exc.code}"
            return
        except urllib.error.URLError as exc:
            ev.status = "unreachable"
            ev.error = str(exc.reason)
            return
        except (TimeoutError, OSError) as exc:
            ev.status = "unreachable"
            ev.error = str(exc)
            return

        ev.http_status = status
        ev.status = "injected" if 200 <= status < 300 else "rejected"


def downtime_entity(ev: Event, wall_now: int) -> dict[str, Any]:
    """Render the event as the exact JSON domain.DowntimeEntity marshals.

    Matching the real schema is what lets the simulator serve these back on
    GET /v1/downtimes with no translation layer, and therefore what lets the
    mesh's downtime client run unmodified against injected outages.
    """
    d = ev.detail
    return {
        "id": ev.downtime_id,
        "entity": "payment.downtime",
        "method": ev.method,
        "begin": wall_now,
        "end": wall_now + int(d["duration_s"]),
        "status": "scheduled" if d["scheduled"] else "started",
        "scheduled": bool(d["scheduled"]),
        "severity": d["severity"],
        "instrument": d["instrument"],
        "created_at": wall_now,
        "updated_at": wall_now,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def validate_target(raw: str, allow_remote: bool) -> str:
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"target must be http or https, got {parsed.scheme or 'no scheme'!r}")
    if not parsed.hostname:
        raise ValueError("target has no host")
    if parsed.hostname not in LOOPBACK_HOSTS and not allow_remote:
        raise ValueError(
            f"refusing to inject chaos into non-loopback host {parsed.hostname!r}; "
            "pass --allow-remote if that is genuinely what you want")
    return raw


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="chaos_simulator.py",
        description="Seeded Poisson-burst outage injection against a running ResilientMesh stack.",
        epilog="Profiles: " + "; ".join(f"{n} = {p.description}" for n, p in PROFILES.items()),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--seed", type=int, default=42,
                   help="seed for every draw; the same seed replays the same timeline")
    p.add_argument("--target", default="http://127.0.0.1:8081",
                   help="base URL of the simulator control surface (MESH_SIMULATOR_ADDR)")
    p.add_argument("--control-prefix", default="/v1/chaos",
                   help="path the control endpoints are rooted at")
    p.add_argument("--rate", type=float, default=4.0,
                   help="outage bursts per minute (Poisson arrival rate)")
    p.add_argument("--duration", type=float, default=120.0,
                   help="length of the run, in seconds")
    p.add_argument("--profile", choices=sorted(PROFILES), default="mixed",
                   help="which failure population to draw from")
    p.add_argument("--out", default="artifacts/chaos_timeline.json",
                   help="where to write the timeline; '-' writes nothing")
    p.add_argument("--dry-run", action="store_true",
                   help="print and write the plan without contacting the target")
    p.add_argument("--allow-remote", action="store_true",
                   help="permit a non-loopback target (off by default on purpose)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                   help="per-request timeout in seconds")
    p.add_argument("--auth-env", default="MESH_OPS_TOKEN",
                   help="environment variable holding the bearer token; never passed as a flag")
    p.add_argument("--max-events", type=int, default=600,
                   help="hard ceiling on planned events")
    p.add_argument("--quiet", action="store_true", help="suppress per-event progress lines")
    return p.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if not 0 <= args.seed <= MAX_SEED:
        raise ValueError(f"--seed must be in [0, {MAX_SEED}]")
    if not 0 < args.rate <= MAX_RATE_PER_MIN:
        raise ValueError(f"--rate must be in (0, {MAX_RATE_PER_MIN}]")
    if not 0 < args.duration <= MAX_DURATION_S:
        raise ValueError(f"--duration must be in (0, {MAX_DURATION_S}] seconds")
    if not 0 < args.max_events <= MAX_EVENTS:
        raise ValueError(f"--max-events must be in (0, {MAX_EVENTS}]")
    if not 0 < args.timeout <= 120:
        raise ValueError("--timeout must be in (0, 120] seconds")
    validate_target(args.target, args.allow_remote)


def print_plan(args: argparse.Namespace, profile: Profile, events: list[Event]) -> None:
    bursts = len({e.burst for e in events})
    failures = sum(e.detail.get("count", 0) for e in events if e.kind == "failure.burst")
    resolutions = sum(1 for e in events if e.kind == "downtime.resolve")
    keys = sorted({e.telemetry_key for e in events})

    print("ResilientMesh chaos injector")
    print(f"  profile     {profile.name} - {profile.description}")
    print(f"  seed        {args.seed}   (same seed, same timeline)")
    print(f"  target      {args.target}{args.control_prefix}"
          + ("   [DRY RUN, nothing is sent]" if args.dry_run else ""))
    print(f"  arrivals    Poisson, {args.rate:g}/min over {args.duration:g}s")
    lo, hi = outage_bounds(profile, args.duration)
    if hi < profile.outage_max_s:
        print(f"  outages     drawn in [{lo}s, {hi}s], capped at 40% of the horizon "
              "so notices resolve inside the run")
    print(f"  planned     {len(events)} events / {bursts} bursts / "
          f"{failures} injected failures / {resolutions} resolutions")
    print(f"  issuers     {', '.join(keys) if keys else '(none)'}")
    print()
    print("  TIME   EVENT               ISSUER                  DETAIL")
    for ev in events:
        print(ev.row())
    print()


def run(args: argparse.Namespace, events: list[Event], injector: Injector) -> int:
    """Walk the schedule in wall-clock time. Returns the count of failed sends.

    Real time rather than a compressed clock: the demo narration is spoken over
    this, and an injector that fires a ten-minute outage in eight seconds tests
    a system nobody operates.
    """
    started = time.monotonic()
    origin = int(time.time())
    failed = 0
    for ev in events:
        wait = ev.offset_s - (time.monotonic() - started)
        if wait > 0:
            time.sleep(wait)
        injector.send(ev, origin + int(ev.offset_s))
        if ev.status != "injected":
            failed += 1
        if not args.quiet:
            mark = "ok " if ev.status == "injected" else "FAIL"
            suffix = f"  ({ev.error})" if ev.error else ""
            print(f"  [{mark}] {ev.row().strip()}{suffix}", flush=True)
    return failed


def write_timeline(path: str, args: argparse.Namespace, profile: Profile,
                   events: list[Event], failed: int) -> None:
    if path == "-":
        return
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    doc = {
        "schema": "resilientmesh.chaos.timeline.v1",
        "seed": args.seed,
        "profile": profile.name,
        "profile_description": profile.description,
        "rate_per_minute": args.rate,
        "duration_s": args.duration,
        "outage_bounds_s": list(outage_bounds(profile, args.duration)),
        # The target is recorded without credentials: the token lives in the
        # environment and is never written to an artifact.
        "target": args.target,
        "control_prefix": args.control_prefix,
        "dry_run": bool(args.dry_run),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "events_planned": len(events),
        "events_failed": failed,
        "events": [e.to_json() for e in events],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        validate_args(args)
    except ValueError as exc:
        print(f"chaos_simulator: {exc}", file=sys.stderr)
        return 2

    profile = PROFILES[args.profile]
    rng = np.random.default_rng(args.seed)
    events = build_plan(rng, profile, args.rate, args.duration, args.max_events)
    print_plan(args, profile, events)

    interrupted = False
    failed = 0
    if args.dry_run:
        # The plan is fully drawn before any I/O, so a dry run has nothing left
        # to do: sleeping through the schedule would only delay the artifact.
        pass
    else:
        token = os.environ.get(args.auth_env) or None
        if token is None:
            print(f"  note: {args.auth_env} is unset; sending without a bearer token", file=sys.stderr)
        injector = Injector(args.target, args.control_prefix, args.timeout, token)
        try:
            failed = run(args, events, injector)
        except KeyboardInterrupt:
            interrupted = True
            failed = sum(1 for e in events if e.status != "injected")
            print("\n  interrupted; writing the timeline as far as it got", file=sys.stderr)

    write_timeline(args.out, args, profile, events, failed)

    delivered = sum(1 for e in events if e.status == "injected")
    print(f"chaos_simulator: {len(events)} planned, {delivered} injected, {failed} failed"
          + ("" if args.out == "-" else f"; timeline written to {args.out}"))

    if interrupted:
        return 130
    if args.dry_run:
        return 0
    # A run whose injections did not land proves nothing, so it must not look
    # like a pass to a harness that only checks the exit code.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
