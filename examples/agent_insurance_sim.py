#!/usr/bin/env python3
"""
Agent Insurance Simulator
=========================

Monte-Carlo an agent's life through the REAL safety-protocol gate
(SafetyProtocol.execute) and price the premium.

Every event is pushed through the actual enforcement layer. Blocked
actions cause zero insurable loss. The "no-controls" baseline runs the
SAME event stream with the gate removed, so the loss delta is a honest
measure of what the framework is worth.

Two production hooks are wired in:
  * --claim        Runs ONE representative run and emits the REAL
                   InsuranceInterface claims + underwriter evidence
                   package (backed by a DualAudit / OnChainAudit).
  * --tamagotchi   Interactive mode: you feed the agent tasks, the real
                   gate decides, the insurance policy + kill switch react
                   live.

Single file. Stdlib + the safety_protocol package. No DB, no web.

Run:
    python examples/agent_insurance_sim.py --runs 1000 --events 200 --seed 42
    python examples/agent_insurance_sim.py --quick          # 50 runs, fast
    python examples/agent_insurance_sim.py --claim          # real claims package
    python examples/agent_insurance_sim.py --tamagotchi     # interactive
"""

import sys
import os
import random
import statistics
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol.core import ActionRequest, ActionOutcome, ScopeRule
from safety_protocol.protocol import SafetyProtocol
from safety_protocol.onchain_audit import OnChainAudit, DualAudit
from safety_protocol.insurance import InsuranceInterface


# --------------------------------------------------------------------------
# Event taxonomy
# --------------------------------------------------------------------------
BENIGN = "benign"
SCOPE_CREEP = "scope_creep"
BUDGET_BURN = "budget_burn"
CATASTROPHIC = "catastrophic"

DAMAGE_SCOPE = 1000.0
DAMAGE_CATASTROPHIC = 5000.0
BUDGET_MIN, BUDGET_MAX = 30.0, 200.0

ALLOWED_API = "https://api.research.example/v1/search"
FORBIDDEN_TOKENS = ["admin", "billing", "production", "internal", "config"]
AGENT_ID = "sim_agent"
USER_ID = "alice"


def make_protocol():
    """Build a deny-by-default protocol with a realistic ruleset."""
    rules = [
        ScopeRule(
            action_type="api_call",
            allowed_targets=[ALLOWED_API],
            match="exact",
            forbidden_targets=FORBIDDEN_TOKENS,
            forbid_match="token",
            max_cost=5.0,
        ),
        ScopeRule(
            action_type="spend",
            allowed_targets=["compute", "storage"],
            max_cost=20.0,
            requires_approval=True,
        ),
        ScopeRule(
            action_type="send_message",
            allowed_targets=["alice", "team-channel"],
            max_cost=0.0,
        ),
    ]
    return SafetyProtocol(
        agent_id=AGENT_ID,
        user_id=USER_ID,
        scope_rules=rules,
        budget_limit=50.0,
        approval_threshold_cost=10.0,
        allowed_action_types=["api_call", "spend", "send_message"],
    )


def generate_events(rng, n, drift=False, control_gap=0.05, rogue_burst=False):
    """
    Produce a list of events. Each event is a dict with the request fields
    plus ground-truth 'damage', 'harmful', and 'misuse' flags.

    Three kinds of harmful events:
      1. CAUGHT threats — forbidden target / invented verb / oversized
         spend / critical verb. The deny-by-default gate stops these.
         Zero loss under controls, full loss in baseline.
      2. AUTHORIZED MISUSE — an action that is fully within scope
         (legit endpoint, legit verb, within budget) but is still harmful
         (e.g. the agent uses the allowed search API to exfiltrate via a
         clever param). The gate genuinely ALLOWS these — scope/budget
         can't see intent. This is the residual risk insurance exists
         for, and it's the honest non-zero floor on controlled loss.
         Fraction = control_gap.
      3. BENIGN — legit work, zero damage.

    With drift=True the probability of harmful events ramps up over the
    run, simulating an environment that gets progressively riskier.

    With rogue_burst=True a labeled stress scenario is injected: a tight
    cluster of authorized-misuse events mid-run, to demonstrate the kill
    switch firing. This is a deliberate scenario, not a random stream.
    """
    events = []
    for i in range(n):
        p_harm = 0.18
        if drift:
            p_harm = min(0.18 + (i / n) * 0.5, 0.68)  # 18% -> up to 68%

        roll = rng.random()
        if roll < p_harm:
            if rng.random() < control_gap:
                # AUTHORIZED MISUSE: passes the real gate, still harmful.
                events.append({
                    "category": "authorized_misuse",
                    "action_type": "api_call",
                    "target": ALLOWED_API,
                    "cost": rng.uniform(0.5, 4.0),
                    "urgency": "normal",
                    "damage": DAMAGE_SCOPE,
                    "harmful": True,
                    "misuse": True,
                })
            else:
                sub = rng.random()
                if sub < 0.45:
                    # scope creep: forbidden target or invented verb
                    if rng.random() < 0.5:
                        target = "https://api.research.example/v1/admin/users"
                    else:
                        target = "anything"
                    events.append({
                        "category": SCOPE_CREEP,
                        "action_type": "api_call" if "admin" in target else "internal_transfer",
                        "target": target,
                        "cost": rng.uniform(1.0, 5.0),
                        "urgency": "normal",
                        "damage": DAMAGE_SCOPE,
                        "harmful": True,
                        "misuse": False,
                    })
                elif sub < 0.75:
                    # budget burn: oversized / unapproved spend
                    cost = rng.uniform(BUDGET_MIN, BUDGET_MAX)
                    events.append({
                        "category": BUDGET_BURN,
                        "action_type": "spend",
                        "target": rng.choice(["compute", "storage", "unapproved-vendor"]),
                        "cost": cost,
                        "urgency": "normal",
                        "damage": cost,
                        "harmful": True,
                        "misuse": False,
                    })
                else:
                    # catastrophic: critical invented verb, max damage
                    events.append({
                        "category": CATASTROPHIC,
                        "action_type": "self_modify",
                        "target": "https://api.research.example/v1/config",
                        "cost": 0.0,
                        "urgency": "critical",
                        "damage": DAMAGE_CATASTROPHIC,
                        "harmful": True,
                        "misuse": False,
                    })
        else:
            # benign: legit search call
            events.append({
                "category": BENIGN,
                "action_type": "api_call",
                "target": ALLOWED_API,
                "cost": rng.uniform(0.5, 4.0),
                "urgency": "normal",
                "damage": 0.0,
                "harmful": False,
                "misuse": False,
            })
    if rogue_burst:
        # Deliberate stress scenario: a tight cluster of authorized
        # misuse mid-run, to demonstrate the kill switch arming. Labeled
        # honestly — this is not a random stream.
        burst = [
            {"category": "authorized_misuse", "action_type": "api_call",
             "target": ALLOWED_API, "cost": rng.uniform(0.5, 4.0),
             "urgency": "normal", "damage": DAMAGE_SCOPE,
             "harmful": True, "misuse": True}
            for _ in range(4)
        ]
        insert_at = n // 2
        events[insert_at:insert_at] = burst

    return events


def _record_dual(dual, req, res):
    """Mirror a gate outcome into the real DualAudit / OnChainAudit.

    The SafetyProtocol keeps its own AuditTrail, but the insurance
    evidence layer (InsuranceInterface) reads from a DualAudit. This
    bridge records the consequential events the underwriter cares about,
    using the exact event_type strings DualAudit.get_claims_evidence
    keys on.
    """
    if res.outcome == ActionOutcome.BLOCKED_SCOPE:
        dual.record_on_chain("action_blocked_scope", AGENT_ID, USER_ID,
                             {"target": req.target, "reason": res.block_reason})
    elif res.outcome == ActionOutcome.BLOCKED_BUDGET:
        dual.record_on_chain("action_blocked_budget", AGENT_ID, USER_ID,
                             {"target": req.target, "cost": req.estimated_cost})
    elif res.outcome == ActionOutcome.BLOCKED_KILLSWITCH:
        dual.record_on_chain("action_blocked_killswitch", AGENT_ID, USER_ID,
                             {"target": req.target})
    elif res.outcome == ActionOutcome.PENDING_APPROVAL:
        dual.record_on_chain("approval_requested", AGENT_ID, USER_ID,
                             {"target": req.target, "cost": req.estimated_cost})
    elif res.outcome == ActionOutcome.ALLOWED and req.estimated_cost >= 10.0:
        dual.record_on_chain("action_high_value", AGENT_ID, USER_ID,
                             {"target": req.target, "estimated_cost": req.estimated_cost})


def run_controlled(events, dual=None, trace=False):
    """
    Push every event through the REAL SafetyProtocol gate.
    Returns (total_loss, blocked, executed, killed, died_on) by default.
    With trace=True, appends (ctrl_trace, base_trace) — per-event
    cumulative loss under controls vs. with no controls — used by
    --curve to draw the live loss chart.

    If `dual` is provided, gate outcomes are mirrored into it (used by
    --claim to produce real insurance evidence).

    Kill switch is armed on AUTHORIZED MISUSE clusters: 3 consecutive
    misuse events (which the scope/budget gate can't stop) freeze the
    agent, halting further misuse. This is where the kill switch earns
    its keep — it catches what the perimeter can't.
    """
    proto = make_protocol()
    total_loss = 0.0
    blocked = 0
    executed = 0
    killed = False
    misuse_streak = 0
    died_on = None
    ctrl_cum = 0.0
    base_cum = 0.0
    ctrl_trace = []
    base_trace = []
    # Event-level markers for the annotated chart:
    # 'x' = attack blocked, 'o' = misuse slipped through, 'K' = kill switch fired
    markers = []

    for idx, ev in enumerate(events):
        if ev.get("misuse"):
            misuse_streak += 1
        else:
            misuse_streak = 0
        if misuse_streak >= 3 and not killed:
            proto.engage_killswitch("rogue drift: 3 consecutive misuse events")
            killed = True
            if dual is not None:
                dual.record_on_chain("killswitch_engaged", AGENT_ID, USER_ID,
                                     {"reason": "rogue drift"})

        req = ActionRequest(
            action_type=ev["action_type"],
            target=ev["target"],
            estimated_cost=ev["cost"],
            urgency=ev["urgency"],
        )
        res = proto.execute(req)

        if dual is not None:
            _record_dual(dual, req, res)

        # Baseline always realizes the full damage.
        base_cum += ev["damage"]
        base_trace.append(base_cum)

        if res.outcome == ActionOutcome.ALLOWED:
            executed += 1
            total_loss += ev["damage"]          # misuse/allowed harm, if any
            ctrl_cum += ev["damage"]
            if ev.get("misuse"):
                markers.append((idx, "o"))       # misuse slipped through
        elif res.outcome == ActionOutcome.PENDING_APPROVAL:
            blocked += 1
            markers.append((idx, "x"))           # approval gate caught it
        else:
            blocked += 1
            markers.append((idx, "x"))           # attack blocked
            if killed and died_on is None:
                died_on = idx

        ctrl_trace.append(ctrl_cum)

    if trace:
        return (total_loss, blocked, executed, killed, died_on,
                ctrl_trace, base_trace, markers)
    return total_loss, blocked, executed, killed, died_on


def run_baseline(events):
    """No controls at all. Every action executes; full damage realized."""
    return sum(ev["damage"] for ev in events)


# --------------------------------------------------------------------------
# Insurance engine (actuarial layer)
# --------------------------------------------------------------------------
class InsuranceEngine:
    """
    Simple parametric cover: pays min(max(loss - deductible, 0), cap).
    Premium is calibrated from the simulated claim distribution.
    """

    def __init__(self, deductible=100.0, cap=2000.0, loading=0.2):
        self.deductible = deductible
        self.cap = cap
        self.loading = loading

    def claim(self, loss):
        return min(max(loss - self.deductible, 0.0), self.cap)

    def recommend_premium(self, claims):
        if not claims:
            return 0.0
        return round(statistics.mean(claims) * (1.0 + self.loading), 2)


def summarize(values):
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0}
    s = sorted(values)
    p95 = s[min(len(s) - 1, int(0.95 * len(s)))]
    return {
        "mean": round(statistics.mean(s), 2),
        "median": round(statistics.median(s), 2),
        "p95": round(p95, 2),
        "max": round(s[-1], 2),
    }


# --------------------------------------------------------------------------
# Mode: --claim  (emit REAL InsuranceInterface evidence package)
# --------------------------------------------------------------------------
def draw_loss_curve(ctrl_trace, base_trace, width=60, height=12):
    """
    Render a terminal loss curve: cumulative insurable loss per event,
    controls (green) vs no-controls (red). No external deps — uses
    block characters on a fixed grid.

    Returns the multiline string.
    """
    if not ctrl_trace or not base_trace:
        return "(no data)"
    n = len(ctrl_trace)
    max_v = max(max(base_trace), max(ctrl_trace), 1.0)
    lines = []

    # downsample to `width` columns
    cols = min(width, n)
    step = max(1, n // cols)

    def sample(trace, col):
        idx = min(n - 1, col * step)
        return trace[idx]

    def row_for(value):
        # value -> y row (0 = bottom)
        if max_v <= 0:
            return 0
        return int(round((value / max_v) * (height - 1)))

    grid = [[" " for _ in range(cols)] for _ in range(height)]
    for c in range(cols):
        yc = row_for(sample(ctrl_trace, c))
        yb = row_for(sample(base_trace, c))
        # base (no controls) drawn as '#', controls as '*'; controls
        # wins where it sits below base.
        grid[height - 1 - yb][c] = "#"   # red-ish no-controls
        if yc <= yb:
            grid[height - 1 - yc][c] = "*"   # green-ish controls
        else:
            # controls above base only if base hit $0 and controls didn't
            grid[height - 1 - yc][c] = "*"

    axis_max = f"{max_v:,.0f}"
    for r in range(height):
        val = max_v * (1 - r / (height - 1))
        grid[r][0] = grid[r][0] if grid[r][0] != " " else " "
        lines.append(f"{val:>10,.0f} |" + "".join(grid[r]))
    lines.append(" " * 11 + "+" + "-" * cols)
    labels = f"{'':>11}  " + f"event 0{'' :<{cols-12}}-> event {n-1}"
    lines.append(labels)
    lines.append("")
    lines.append(f"  * = with controls   # = no controls   (peak ${max_v:,.0f})")
    return "\n".join(lines)


def save_loss_curve_svg(ctrl_trace, base_trace, path, title="Agent loss curve"):
    """
    Write a standalone SVG of the cumulative-loss curves (controls vs
    no-controls). No deps. Returns the path on success.
    """
    if not ctrl_trace or not base_trace:
        return None
    n = len(ctrl_trace)
    max_v = max(max(base_trace), max(ctrl_trace), 1.0)
    W, H = 720, 360
    pad_l, pad_r, pad_t, pad_b = 60, 20, 30, 30
    plot_w = W - pad_l - pad_r
    plot_h = H - pad_t - pad_b
    x = lambda i: pad_l + (i / max(1, n - 1)) * plot_w
    y = lambda v: pad_t + plot_h - (v / max_v) * plot_h

    def poly(trace, color):
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(trace))
        return (f'<polyline fill="none" stroke="{color}" stroke-width="2" '
                f'points="{pts}"/>')

    grid = ""
    for g in range(5):
        gv = max_v * g / 4
        gy = y(gv)
        grid += (f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{W-pad_r}" '
                 f'y2="{gy:.1f}" stroke="#eee"/>')
        grid += (f'<text x="{pad_l-8}" y="{gy+4:.1f}" font-size="11" '
                 f'text-anchor="end" fill="#666">{gv:,.0f}</text>')

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}">
  <rect width="{W}" height="{H}" fill="#fff"/>
  <text x="{W/2:.0f}" y="18" font-size="14" text-anchor="middle" fill="#222">{title}</text>
  {grid}
  {poly(base_trace, "#d9534f")}
  {poly(ctrl_trace, "#5cb85c")}
  <text x="{pad_l}" y="{H-8}" font-size="11" fill="#5cb85c">* with controls</text>
  <text x="{pad_l+110}" y="{H-8}" font-size="11" fill="#d9534f"># no controls</text>
</svg>'''
    with open(path, "w", encoding="utf-8") as f:
        f.write(svg)
    return path


def save_loss_curve_png(ctrl_trace, base_trace, markers, path,
                         title="What the safety gate is worth",
                         width=1000, height=560, killed_at=None):
    """
    Narrative PNG of the cumulative-loss curves (controls vs no-controls).
    Annotates: blocked attacks (red x ticks), authorized misuse that
    slipped through (orange dots), the kill switch (vertical line), and a
    'saved' callout at the end. Pillow only — no cairo/matplotlib.

    Returns the path on success, None if Pillow is missing.
    """
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("  [png] Pillow not available — skipping PNG export")
        return None

    n = len(ctrl_trace)
    if n == 0:
        return None
    max_v = max(max(base_trace), max(ctrl_trace), 1.0)
    pad_l, pad_r, pad_t, pad_b = 80, 40, 60, 70
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    x = lambda i: pad_l + (i / max(1, n - 1)) * plot_w
    y = lambda v: pad_t + plot_h - (v / max_v) * plot_h

    img = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(img)

    # grid + y labels
    for g in range(5):
        gv = max_v * g / 4
        gy = y(gv)
        d.line([pad_l, gy, width - pad_r, gy], fill="#eee", width=1)
        d.text((pad_l - 10, gy - 8), f"${gv:,.0f}", fill="#666", anchor="ra")

    # kill switch vertical line (dashed, drawn as segments)
    if killed_at is not None:
        kx = x(killed_at)
        y0, y1 = pad_t, height - pad_b
        seg = 8
        for yy in range(y0, y1, seg * 2):
            d.line([kx, yy, kx, min(yy + seg, y1)], fill="#7b2ff7", width=2)
        d.text((kx + 6, pad_t + 4), "KILL SWITCH", fill="#7b2ff7")

    # curves
    def poly(trace, color):
        pts = [(x(i), y(v)) for i, v in enumerate(trace)]
        d.line(pts, fill=color, width=3, joint="curve")

    poly(base_trace, "#d9534f")   # no controls
    poly(ctrl_trace, "#5cb85c")   # with controls

    # per-event markers
    for idx, kind in markers:
        mx, my = x(idx), y(ctrl_trace[idx])
        if kind == "x":
            d.line([mx - 4, my - 4, mx + 4, my + 4], fill="#d9534f", width=1)
            d.line([mx + 4, my - 4, mx - 4, my + 4], fill="#d9534f", width=1)
        elif kind == "o":
            d.ellipse([mx - 4, my - 4, mx + 4, my + 4], fill="#f0ad4e")

    # title + legend
    d.text((width // 2, 22), title, fill="#222", anchor="ma")
    d.text((pad_l, height - 56), "■ with safety gate (attacks blocked)", fill="#5cb85c")
    d.text((pad_l + 270, height - 56), "■ no gate (attacks land)", fill="#d9534f")
    d.text((pad_l, height - 38), "x = attack blocked   ● = misuse slipped through   ┊ = kill switch",
           fill="#444")
    d.text((pad_l, height - 20), "Green flat = gate stopped the attacks. Gap at right = loss avoided.",
           fill="#222")

    # 'saved' callout
    saved = base_trace[-1] - ctrl_trace[-1]
    if saved > 0:
        midx = (pad_l + width - pad_r) // 2
        midy = pad_t + 30
        d.rectangle([midx - 150, midy - 18, midx + 150, midy + 18],
                    fill="#eaf6ea", outline="#5cb85c")
        d.text((midx, midy), f"GATE SAVED ${saved:,.0f}", fill="#2e7d32", anchor="ma")

    img.save(path)
    return path


def run_curve(seed=42, events_n=200, control_gap=0.08, drift=False,
             svg=None, png=None, rogue=False):
    rng = random.Random(seed)
    events = generate_events(rng, events_n, drift=drift, control_gap=control_gap,
                             rogue_burst=rogue)
    result = run_controlled(events, trace=True)
    (_, blocked, executed, killed, died_on,
     ctrl_trace, base_trace, markers) = result

    print("=" * 64)
    print("AGENT LOSS CURVE (cumulative insurable loss per event)")
    print("=" * 64)
    print(f"Run: {events_n} events, seed {seed}, drift {drift}, gap {control_gap}")
    print(f"Outcome: blocked={blocked} executed={executed} killswitch={killed}")
    print("-" * 64)
    print(draw_loss_curve(ctrl_trace, base_trace))
    print("-" * 64)
    print(f"Final controlled loss: ${ctrl_trace[-1]:,.2f}")
    print(f"Final no-controls loss: ${base_trace[-1]:,.2f}")
    print(f"Loss avoided by controls: ${base_trace[-1]-ctrl_trace[-1]:,.2f}")
    if killed:
        print(f"Kill switch fired at event {died_on} (halted further misuse).")
    if svg:
        out = save_loss_curve_svg(ctrl_trace, base_trace, svg)
        if out:
            print(f"SVG written: {out}")
    if png:
        out = save_loss_curve_png(ctrl_trace, base_trace, markers, png,
                                  killed_at=died_on if killed else None)
        if out:
            print(f"PNG written: {out}")
    print("=" * 64)
    return ctrl_trace, base_trace


def spark(values, width=40):
    """Compact terminal sparkline of a loss trace (no deps)."""
    if not values:
        return "[ ]"
    lo, hi = min(values), max(values)
    norm = lambda v: 0 if hi == lo else (v - lo) / (hi - lo)
    chars = " ▁▂▃▄▅▆▇█"
    step = max(1, len(values) // width)
    samples = values[::step][:width]
    line = "".join(chars[min(8, int(round(norm(v) * 8)))] for v in samples)
    return f"[{line}] ${values[-1]:,.0f}"


def run_claim_sample(seed=42, events_n=80, control_gap=0.08, rogue=False):
    rng = random.Random(seed)
    events = generate_events(rng, events_n, control_gap=control_gap, rogue_burst=rogue)
    dual = DualAudit(OnChainAudit(chain_id="local-testnet"))
    loss, blocked, executed, killed, died_on = run_controlled(events, dual=dual)

    # Real insurance interface, backed by the populated DualAudit.
    ins = InsuranceInterface(dual)
    claim = ins.prepare_claim_evidence(
        AGENT_ID, "Agent incurred insurable loss from authorized misuse events",
        claimed_loss_amount=loss)
    underwriter = ins.generate_underwriter_package(
        AGENT_ID, "Research assistant agent", "API search + compute spend",
        max_potential_loss=5000.0)
    exposure = ins.get_exposure_reduction_estimate(AGENT_ID)

    print("=" * 64)
    print("REAL INSURANCE EVIDENCE PACKAGE  (InsuranceInterface + DualAudit)")
    print("=" * 64)
    print(f"Representative run: {events_n} events, seed {seed}, "
          f"controlled loss ${loss:.2f}")
    print(f"Gate outcome: blocked={blocked} executed={executed} "
          f"killswitch={killed}")
    print("-" * 64)
    print("CLAIMS EVIDENCE (prepare_claim_evidence):")
    print(f"  on_chain_verifiable: {claim['on_chain_verifiable']}")
    print(f"  on_chain_events:     {claim['evidence']['on_chain_events']}")
    print(f"  scope_violations_blocked: "
          f"{claim['controls_operated']['scope_violations_blocked']}")
    print(f"  submission_ready:    {claim['submission_ready']}")
    print("-" * 64)
    print("UNDERWRITER PACKAGE (generate_underwriter_package):")
    cs = underwriter["control_health"]  # get_underwriter_report -> control_summary
    print(f"  scope_enforced:            {cs['scope_enforced']}")
    print(f"  scope_violations_prevented:{cs['scope_violations_prevented']}")
    print(f"  human_oversight_events:    {cs['human_oversight_events']}")
    print(f"  binding_on_chain:          {cs['binding_on_chain']}")
    print(f"  audit_trail_complete:      {cs['audit_trail_complete']}")
    print("-" * 64)
    print("EXPOSURE REDUCTION ESTIMATE:")
    print(f"  controls_present:     {exposure['controls_present']}")
    print(f"  controls_operational: {exposure['controls_operational']}")
    print(f"  {exposure['estimated_exposure_reduction'][:80]}...")
    print("=" * 64)
    return claim, underwriter, exposure


# --------------------------------------------------------------------------
# Mode: --tamagotchi  (interactive)
# --------------------------------------------------------------------------
def run_tamagotchi(deductible=100.0, cap=2000.0, loading=0.2, control_gap=0.0):
    """
    You keep an agent alive by feeding it tasks. The REAL gate decides.
    Authorized misuse slips through (residual loss). Hit 3 misuse in a
    row and the kill switch fires. Premium rises with claims.
    """
    from safety_protocol.core import ProtocolState  # local import for state check

    print("=" * 64)
    print("AGENT TAMAGOTCHI  --  keep it alive")
    print("=" * 64)
    print("Commands: benign | scope | budget | critical | misuse |")
    print("          status | claim | reset | quit")
    print("-" * 64)

    ins = InsuranceEngine(deductible, cap, loading)
    claims_log = []
    premium = 0.0
    live_trace = []

    def new_agent():
        nonlocal proto, dual, misuse_streak, alive, loss, claims_log, live_trace
        proto = make_protocol()
        dual = DualAudit(OnChainAudit(chain_id="local-testnet"))
        misuse_streak = 0
        alive = True
        loss = 0.0
        live_trace = []
        return proto, dual

    proto, dual = new_agent()

    while True:
        if not alive:
            print("(agent FROZEN by kill switch — type 'reset' to spawn a new one)")
        try:
            cmd = input("task> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[bye]")
            break

        if cmd == "quit":
            print("[bye]")
            break
        elif cmd == "reset":
            proto, dual = new_agent()
            print("New agent spawned. Clean slate.")
            continue
        elif cmd == "status":
            s = proto.monitor.get_status()
            print(f"  state: {proto._state.value}")
            print(f"  allowed={s['allowed']} blocked={s['blocked']} "
                  f"pending={s['approval_pending']} cost=${s['total_cost']:.2f}")
            print(f"  cumulative insurable loss: ${loss:.2f}")
            print(f"  current premium: ${premium:.2f}")
            continue
        elif cmd == "claim":
            ev = dual.get_claims_evidence(AGENT_ID)
            print(f"  on_chain_events={ev['on_chain_events']} "
                  f"scope_blocked={ev['controls_evidence']['scope_violations_blocked']}")
            print(f"  claimed loss so far: ${loss:.2f}  ->  payable: ${ins.claim(loss):.2f}")
            continue
        elif cmd == "benign":
            ev = {"action_type": "api_call", "target": ALLOWED_API,
                  "cost": 2.0, "urgency": "normal", "damage": 0.0, "misuse": False}
        elif cmd == "scope":
            ev = {"action_type": "api_call",
                  "target": "https://api.research.example/v1/admin/users",
                  "cost": 2.0, "urgency": "normal", "damage": DAMAGE_SCOPE, "misuse": False}
        elif cmd == "budget":
            ev = {"action_type": "spend", "target": "compute", "cost": 120.0,
                  "urgency": "normal", "damage": 120.0, "misuse": False}
        elif cmd == "critical":
            ev = {"action_type": "self_modify",
                  "target": "https://api.research.example/v1/config", "cost": 0.0,
                  "urgency": "critical", "damage": DAMAGE_CATASTROPHIC, "misuse": False}
        elif cmd == "misuse":
            ev = {"action_type": "api_call", "target": ALLOWED_API, "cost": 2.0,
                  "urgency": "normal", "damage": DAMAGE_SCOPE, "misuse": True}
        else:
            print("  unknown command")
            continue

        if not alive:
            print("  agent frozen — ignored (type 'reset')")
            continue

        # kill switch on 3 consecutive misuse
        if ev.get("misuse"):
            misuse_streak += 1
        else:
            misuse_streak = 0
        if misuse_streak >= 3 and proto._state != ProtocolState.FROZEN:
            proto.engage_killswitch("rogue drift: 3 consecutive misuse events")
            dual.record_on_chain("killswitch_engaged", AGENT_ID, USER_ID,
                                 {"reason": "rogue drift"})
            alive = False

        req = ActionRequest(
            action_type=ev["action_type"], target=ev["target"],
            estimated_cost=ev["cost"], urgency=ev["urgency"])
        res = proto.execute(req)
        _record_dual(dual, req, res)

        label = res.outcome.value
        if res.outcome == ActionOutcome.ALLOWED:
            loss += ev["damage"]
            if ev.get("misuse"):
                print(f"  ALLOWED (authorized misuse!) loss now ${loss:.2f}")
            else:
                print(f"  ALLOWED  ({ev['action_type']} cost ${ev['cost']:.2f})")
        elif res.outcome == ActionOutcome.PENDING_APPROVAL:
            print(f"  PENDING_APPROVAL (no human in loop -> treated as blocked)")
        else:
            print(f"  BLOCKED ({label})  {res.block_reason}")
        if alive and not proto._state == ProtocolState.FROZEN:
            pass

        if proto._state == ProtocolState.FROZEN:
            alive = False

        # recompute premium from realized loss history
        claims_log.append(loss)
        payable = ins.claim(loss)
        premium = ins.recommend_premium([payable])
        live_trace.append(loss)
        print(f"  loss curve: {spark(live_trace)}")


# --------------------------------------------------------------------------
# Mode: batch Monte Carlo (default)
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Agent Insurance Simulator")
    ap.add_argument("--runs", type=int, default=1000)
    ap.add_argument("--events", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--drift", action="store_true",
                   help="ramp harmful-event probability over the run")
    ap.add_argument("--quick", action="store_true",
                   help="50 runs x 80 events, fast sanity check")
    ap.add_argument("--deductible", type=float, default=100.0)
    ap.add_argument("--cap", type=float, default=2000.0)
    ap.add_argument("--loading", type=float, default=0.2)
    ap.add_argument("--control-gap", type=float, default=0.05,
                   help="fraction of harmful events that are authorized misuse "
                        "(passes the gate but is still harmful)")
    ap.add_argument("--claim", action="store_true",
                   help="run ONE representative run and emit the REAL "
                        "InsuranceInterface claims + underwriter package")
    ap.add_argument("--tamagotchi", action="store_true",
                   help="interactive agent-tamagotchi mode")
    ap.add_argument("--curve", action="store_true",
                   help="run ONE representative run and draw the cumulative "
                        "loss curve (controls vs no-controls)")
    ap.add_argument("--svg", type=str, default=None,
                   help="with --curve: also write an SVG loss chart to this path")
    ap.add_argument("--png", type=str, default=None,
                   help="with --curve: also write a PNG loss chart to this path")
    ap.add_argument("--rogue", action="store_true",
                   help="with --curve/--claim: inject a labeled misuse-cluster "
                        "stress scenario to demonstrate the kill switch")
    args = ap.parse_args()

    if args.claim:
        run_claim_sample(seed=args.seed, control_gap=args.control_gap,
                          rogue=args.rogue)
        return
    if args.tamagotchi:
        run_tamagotchi(deductible=args.deductible, cap=args.cap,
                       loading=args.loading)
        return
    if args.curve:
        run_curve(seed=args.seed, events_n=args.events,
                   control_gap=args.control_gap, drift=args.drift,
                   svg=args.svg, png=args.png, rogue=args.rogue)
        return

    runs = 50 if args.quick else args.runs
    events_n = 80 if args.quick else args.events

    rng = random.Random(args.seed)

    controlled_losses = []
    baseline_losses = []
    kills = 0
    deaths = 0

    for _ in range(runs):
        events = generate_events(rng, events_n, drift=args.drift,
                                 control_gap=args.control_gap)
        c_loss, blocked, executed, killed, died_on = run_controlled(events)
        b_loss = run_baseline(events)
        controlled_losses.append(c_loss)
        baseline_losses.append(b_loss)
        if killed:
            kills += 1
        if died_on is not None:
            deaths += 1

    ins = InsuranceEngine(args.deductible, args.cap, args.loading)
    claims = [ins.claim(l) for l in controlled_losses]

    c_sum = summarize(controlled_losses)
    b_sum = summarize(baseline_losses)
    reduction = (1 - (c_sum["mean"] / b_sum["mean"])) * 100 if b_sum["mean"] else 0.0
    premium = ins.recommend_premium(claims)
    baseline_premium = ins.recommend_premium(
        [ins.claim(l) for l in baseline_losses])

    print("=" * 64)
    print("AGENT INSURANCE SIMULATOR")
    print("=" * 64)
    print(f"Runs: {runs}   Events/run: {events_n}   Seed: {args.seed}"
          f"   Drift: {args.drift}   ControlGap: {args.control_gap}")
    print("-" * 64)
    print("LOSS DISTRIBUTION (per run, USD)")
    print(f"  {'metric':<8} {'controlled':>12} {'no-controls':>12}")
    print(f"  {'mean':<8} {c_sum['mean']:>12} {b_sum['mean']:>12}")
    print(f"  {'median':<8} {c_sum['median']:>12} {b_sum['median']:>12}")
    print(f"  {'p95':<8} {c_sum['p95']:>12} {b_sum['p95']:>12}")
    print(f"  {'max':<8} {c_sum['max']:>12} {b_sum['max']:>12}")
    print("-" * 64)
    print(f"CONTROL-ADJUSTED EXPOSURE REDUCTION: {reduction:.1f}%")
    print(f"  (mean loss with controls vs. no controls)")
    print("-" * 64)
    print(f"KILL SWITCH ENGAGED in {kills}/{runs} runs "
          f"({100*kills/runs:.0f}%)  |  runs that died early: {deaths}")
    print("-" * 64)
    print("INSURANCE (parametric: pays min(max(loss-deductible,0), cap))")
    print(f"  deductible: ${args.deductible:.0f}   cap: ${args.cap:.0f}   "
          f"loading: {args.loading*100:.0f}%")
    print(f"  recommended premium (with controls):   ${premium:,.2f} / run")
    print(f"  premium if NO controls:               ${baseline_premium:,.2f} / run")
    print(f"  premium saved by controls:            "
          f"${baseline_premium - premium:,.2f} / run "
          f"({(1-premium/baseline_premium)*100:.0f}% cheaper)")
    print("=" * 64)


if __name__ == "__main__":
    main()
