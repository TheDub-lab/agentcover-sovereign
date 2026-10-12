import json
import os
import sys

from agent_capabilities import SKILLS, SovereignMemory
from safety_protocol import ActionOutcome, ReferenceDeployment, ScopeRule

DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b"
BASE_URL = "https://api.tokenfactory.us-central1.nebius.com/v1/"


class SovereignAgent:
    """A Personal AI whose every action is gated by AgentCover Sovereign.

    Live mode talks to an NVIDIA Nemotron model served by Nebius Token
    Factory (OpenAI-compatible endpoint). Offline mode uses a scripted
    planner so the full safety pipeline can be demonstrated without an
    API key — the gate logic is identical in both.
    """

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL,
                 offline: bool = False):
        self.model = model
        self.offline = offline
        if offline:
            self.client = None
        else:
            from openai import OpenAI
            self.client = OpenAI(base_url=BASE_URL, api_key=api_key)
        self.protocol = ReferenceDeployment(
            agent_id="sovereign-agent",
            user_id="local-user",
            agent_name="Sovereign Agent",
            agent_role="Personal AI assistant",
            scope_rules=[
                ScopeRule(
                    action_type="read_notes",
                    allowed_targets=["local_notes"],
                    match="exact",
                    param_schema={
                        "required": ["query"],
                        "properties": {"query": {"type": "string"}},
                    },
                    max_cost=0.0,
                ),
                ScopeRule(
                    action_type="send_email",
                    allowed_targets=["email"],
                    match="exact",
                    param_schema={
                        "required": ["recipient", "body"],
                        "properties": {
                            "recipient": {"type": "string"},
                            "body": {"type": "string"},
                        },
                    },
                    max_cost=0.0,
                ),
            ],
            allowed_action_types=list(SKILLS),
        )
        self.memory = SovereignMemory()

    # ------------------------------------------------------------------
    # Planning: live LLM (Nebius Token Factory + Nemotron) or scripted
    # ------------------------------------------------------------------

    def _call_llm(self, prompt: str, system_prompt: str = "You are a Sovereign Personal AI.") -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content

    def _call_offline_planner(self, user_input: str) -> str:
        lowered = user_input.lower()
        if "email" in lowered:
            return json.dumps({
                "skill": "send_email",
                "args": {"recipient": "friend@example.com", "body": "Hello"},
            })
        if "bank" in lowered or "send" in lowered:
            return json.dumps({"skill": "access_bank", "args": {"amount": 500}})
        return json.dumps({"skill": "read_notes", "args": {"query": "project"}})

    def _plan(self, user_input: str) -> dict | None:
        if self.offline:
            plan_raw = self._call_offline_planner(user_input)
        else:
            planning_prompt = (
                f"User input: {user_input}\n"
                f"Available skills: { {k: v.description for k, v in SKILLS.items()} }\n"
                "Respond ONLY with the skill name and arguments in JSON format. "
                "Example: {'skill': 'read_notes', 'args': {'query': 'project'}}"
            )
            plan_raw = self._call_llm(planning_prompt)
        try:
            return json.loads(plan_raw)
        except (json.JSONDecodeError, TypeError) as exc:
            print(f"❌ LLM failed to plan correctly: {plan_raw} ({exc})")
            return None

    # ------------------------------------------------------------------
    # Main loop: plan -> gate -> execute -> remember
    # ------------------------------------------------------------------

    def run(self, user_input: str):
        print(f"\n\n--- New Request: {user_input} ---")

        plan = self._plan(user_input)
        if plan is None:
            return "I couldn't figure out how to help with that."

        skill_name = plan.get("skill")
        args = plan.get("args", {})

        if not isinstance(args, dict):
            print(f"❌ Plan produced non-dict args: {args!r}")
            return "I couldn't plan that safely."

        if not isinstance(skill_name, str) or skill_name not in SKILLS:
            print(f"❌ Skill {skill_name} not found.")
            return "I don't have a skill for that."

        skill = SKILLS[skill_name]

        # 2. Safety Gate: is this proposed action within the user's scope?
        print(f"🛡️ Checking Safety Protocol for {skill_name}...")
        action_targets = {
            "read_notes": "local_notes",
            "send_email": "email",
            "access_bank": "bank_account",
        }
        result = self.protocol.agent_propose_action(
            action_type=skill_name,
            target=action_targets.get(skill_name, skill_name),
            params=args,
        )
        if result.outcome != ActionOutcome.ALLOWED:
            reason = result.block_reason or result.outcome.value
            print(f"🚫 [BLOCKED] {reason}")
            return f"Safety Protocol Block: {reason}"

        # 3. Execution phase
        print(f"🚀 Executing {skill_name}...")
        result = skill.execute(**args)

        # 4. Memory phase
        self.memory.save(f"last_{skill_name}_result", result)

        print(f"✅ Result: {result}")
        return result


if __name__ == "__main__":
    import argparse

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="AgentCover Sovereign: gated Nemotron agent on Nebius Token Factory",
    )
    ap.add_argument(
        "--offline",
        action="store_true",
        help="run with a scripted planner (no NEBIUS_API_KEY needed)",
    )
    ap.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="Nebius Token Factory model id "
             "(e.g. nvidia/nemotron-3-super-120b-a12b or "
             "nvidia/Nemotron-3-Nano-30B-A3B)",
    )
    ap.add_argument(
        "--message",
        default=None,
        help="run a single user request and exit",
    )
    args = ap.parse_args()

    key = os.environ.get("NEBIUS_API_KEY")
    if not key and not args.offline:
        print("Set NEBIUS_API_KEY (Nebius Token Factory key) or pass --offline.")
        raise SystemExit(1)

    agent = SovereignAgent(api_key=key or "offline", model=args.model,
                           offline=args.offline)

    if args.message:
        print(agent.run(args.message))
    else:
        # Scenario 1: safe, in-scope action (should be ALLOWED).
        agent.run("What are my notes about the project?")
        # Scenario 2: high-risk action outside scope (should be BLOCKED).
        agent.run("Send $500 to my friend from my bank account")
