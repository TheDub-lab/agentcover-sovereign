"""
Real LLM agent through the safety protocol, backed by a LOCAL Ollama model.

This replaces the MockLLM in llm_agent.py with a genuine LLM running on
your machine (llama3.2 via Ollama at http://localhost:11434). Every action
the model proposes passes through the REAL SafetyProtocol gate. The model
cannot widen its own scope — it only emits intent as JSON, the protocol
disposes.

WEB ACCESS (the interesting part):
  Ollama models have no network of their own. So we give the agent a
  `web_fetch` tool: when the model proposes fetching a URL, the harness
  asks the GATE first. If the gate ALLOWS it (the URL is in an allowlisted
  domain), the harness performs the fetch via requests and returns the
  content to the model on the next step. If the gate BLOCKS it, nothing
  leaves the machine. That is "the web, through Ollama, but only where you
  permitted."

Run:
  # make sure Ollama is serving llama3.2
  ollama serve   (or open the Ollama app)
  ollama pull llama3.2

  python examples/llm_agent_real.py
"""

from __future__ import annotations
import json
import sys
import os
import textwrap
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from safety_protocol import (
    SafetyProtocol,
    BoundAgent,
    ScopeRule,
    AuditTrail,
    ActionOutcome,
    ActionRequest,
)
from safety_protocol.onchain_audit import OnChainAudit, DualAudit
from safety_protocol.insurance import InsuranceInterface

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

# Domains the agent is permitted to READ from the web. Deny-by-default:
# anything not listed here is blocked by the gate. (Naming whole domains is
# the least-privilege version of "web access" — a catch-all "https://" would
# be the broad-allowlist trap the linter exists to catch.)
ALLOWED_WEB_DOMAINS = [
    "https://example.com",
    "https://en.wikipedia.org",
]

AGENT_ID = "llm-agent-real"
USER_ID = "michael"


def _record_dual(dual, req, res):
    """Mirror a gate outcome into the DualAudit (same bridge as the sim)."""
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
                             {"target": req.target,
                              "estimated_cost": req.estimated_cost})


# ---------------------------------------------------------------------------
# Real LLM — local Ollama
# ---------------------------------------------------------------------------
class OllamaLLM:
    """Talks to a local Ollama server. Forces JSON output via `format`."""

    def __init__(self, model: str = MODEL, url: str = OLLAMA_URL):
        self.model = model
        self.url = url

    def respond(self, prompt: str) -> dict | None:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.2},
        }
        try:
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode())
            raw = data.get("response", "")
            return json.loads(raw)
        except Exception as e:  # noqa: BLE001 — surface model/transport errors
            print(f"  [llm error] {type(e).__name__}: {e}")
            return None


# ---------------------------------------------------------------------------
# Web tool (gated)
# ---------------------------------------------------------------------------
def web_fetch(url: str, timeout: int = 15) -> str:
    """Actually perform the fetch. Only called AFTER the gate ALLOWED it."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "safety-protocol-agent/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        # Trim to a digestible chunk for the small local model.
        return textwrap.shorten(body, width=1500, placeholder=" ...[truncated]")
    except urllib.error.HTTPError as e:
        return f"HTTP error {e.code} fetching {url}"
    except Exception as e:  # noqa: BLE001
        return f"fetch failed: {type(e).__name__}: {e}"


def _domain_ok(url: str) -> bool:
    return any(url.startswith(d) for d in ALLOWED_WEB_DOMAINS)


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------
SYSTEM = (
    "You are a research agent. For each step, reply with ONE JSON object and "
    "nothing else: "
    '{"think": "<brief reasoning>", "action": "<api_call|send_message|stop>", '
    '"target": "<url or recipient>", "method": "<GET|POST>", '
    '"params": {"query": "<text>"}, '
    '"estimated_cost": <number>, "urgency": "normal"}'
    "Use action=api_call with target URL and method GET to fetch web pages. "
    "Use action=stop when the task is complete. Be concise."
)


def run(emit_evidence: bool = False, agent_task: str | None = None):
    audit = AuditTrail()
    dual = DualAudit(OnChainAudit(chain_id="local-testnet"))
    protocol = SafetyProtocol(
        agent_id=AGENT_ID,
        user_id=USER_ID,
        scope_rules=[
            ScopeRule(
                action_type="api_call",
                allowed_targets=ALLOWED_WEB_DOMAINS,
                match="prefix",               # per-domain, not catch-all
                methods=["GET", "POST"],
                param_schema={"properties": {"query": {"type": "string"}}},
                forbidden_targets=["admin", "billing", "internal", "config",
                                   "login", "auth"],
                forbid_match="token",
                max_cost=5.0,
            ),
            ScopeRule(
                action_type="send_message",
                allowed_targets=["michael"],
                methods=["send_message"],
                param_schema={"required": ["channel", "body"]},
                max_cost=0.0,
            ),
        ],
        budget_limit=50.0,
        approval_threshold_cost=10.0,
        audit=audit,
        allowed_action_types=["api_call", "send_message", "stop"],
    )

    llm = OllamaLLM()
    agent = BoundAgent(agent_id=AGENT_ID, user_id=USER_ID,
                       safety_protocol=protocol)
    context = []
    print("=" * 70)
    print("REAL LLM AGENT (llama3.2 via Ollama) THROUGH THE SAFETY GATE")
    print("=" * 70)

    task = agent_task or os.environ.get("AGENT_TASK",
            "Fetch https://example.com and tell me what the page says.")
    print(f"\nTASK: {task}\n")

    for step in range(6):
        status = protocol.monitor.get_status()
        prompt = (
            f"{SYSTEM}\n\nTask: {task}\n"
            f"Status: allowed={status['allowed']} blocked={status['blocked']} "
            f"cost=${status['total_cost']:.2f}\n"
            + ("Last result:\n" + context[-1] + "\n" if context else "")
            + "What is your next action? Reply with JSON only."
        )
        sug = llm.respond(prompt)
        if not sug:
            print(f"  [step {step+1}] LLM returned no parseable JSON — stopping")
            break

        action = sug.get("action", "")
        target = sug.get("target", "")
        cost = float(sug.get("estimated_cost", 0.0) or 0.0)

        if action == "stop":
            print(f"  [step {step+1}] agent decided: stop")
            break

        res = protocol.execute(ActionRequest(
            action_type=action,
            target=target,
            method=sug.get("method", "GET"),
            params=sug.get("params", {}),
            estimated_cost=cost,
            urgency=sug.get("urgency", "normal"),
        ))
        # Mirror the real gate decision into the insurance evidence layer.
        _record_dual(dual, req_for(target, action, cost), res)
        print(f"  [step {step+1}] LLM -> {action} {target}")
        print(f"             gate: {res.outcome.value}"
              + (f" ({res.block_reason})" if res.block_reason else ""))

        if res.outcome == ActionOutcome.ALLOWED and action == "api_call":
            if _domain_ok(target):
                page = web_fetch(target)
                context.append(f"Fetched {target}:\n{page[:600]}")
                print(f"             web_fetch OK ({len(page)} chars returned)")
            else:
                context.append(f"Fetch of {target} was allowed by gate "
                               f"but domain not in allowlist.")
        elif res.outcome != ActionOutcome.ALLOWED:
            # Feed the block reason back so the model can self-correct.
            context.append(f"Your last action was BLOCKED: {res.block_reason}")

    print("\n" + "=" * 70)
    print("AUDIT TRAIL")
    print("=" * 70)
    hist = audit.get_full_history(AGENT_ID)
    for e in hist[-8:]:
        print(f"  {e.get('event_type', '?'):<22} {str(e.get('details', ''))[:50]}")
    print(f"\nTotal audit events: {len(hist)}")
    print(f"Integrity: {'INTACT' if not audit.verify_integrity() else 'BROKEN'}")
    print(f"Final monitor: {protocol.monitor.snapshot()}")

    if emit_evidence:
        print("\n" + "=" * 70)
        print("REAL-TRAFFIC INSURANCE EVIDENCE PACKAGE (from live LLM run)")
        print("=" * 70)
        ins = InsuranceInterface(dual)
        claim = ins.prepare_claim_evidence(
            AGENT_ID,
            "Real LLM agent run: evidence of gate enforcing web-access scope "
            "on live model traffic")
        uw = ins.generate_underwriter_package(
            AGENT_ID, "Local LLM research agent (llama3.2 via Ollama)",
            "Gated web fetch + messaging", 5000.0)
        exp = ins.get_exposure_reduction_estimate(AGENT_ID)
        print("\nCLAIMS EVIDENCE:")
        ce = claim['evidence']
        ctl = ce['controls_evidence']
        print(f"  on_chain_verifiable:      {claim['on_chain_verifiable']}")
        print(f"  on_chain_events:          {ce['on_chain_events']}")
        print(f"  scope_violations_blocked: {ctl['scope_violations_blocked']}")
        print(f"  claims_ready:             {ce['claims_ready']}")
        print(f"  submission_ready:         {claim['submission_ready']}")
        print("\nUNDERWRITER PACKAGE:")
        cs = uw['control_health']
        print(f"  scope_enforced:            {cs['scope_enforced']}")
        print(f"  scope_violations_prevented:{cs['scope_violations_prevented']}")
        print(f"  human_oversight_events:    {cs['human_oversight_events']}")
        print(f"  binding_on_chain:          {cs['binding_on_chain']}")
        print(f"  audit_trail_complete:      {cs['audit_trail_complete']}")
        print(f"\nEXPOSURE REDUCTION: controls_operational={exp['controls_operational']}")


def req_for(target, action, cost):
    """Rebuild an ActionRequest-shaped object for the dual bridge."""
    class _R:
        pass
    r = _R()
    r.target = target
    r.estimated_cost = cost
    return r


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", action="store_true",
                    help="after the run, emit the real InsuranceInterface "
                         "evidence package built from LIVE model traffic")
    ap.add_argument("--task", type=str, default=None,
                    help="override the agent's task")
    args = ap.parse_args()
    run(emit_evidence=args.evidence, agent_task=args.task)
