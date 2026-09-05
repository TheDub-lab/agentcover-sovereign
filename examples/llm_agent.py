"""
Example: An LLM-powered agent operating through the safety protocol.

This demonstrates how a real agent — one that uses an LLM to decide what
to do — operates through the safety protocol. The LLM proposes actions,
the protocol enforces the rules.

The agent is given a task, uses an LLM to plan and execute, but every
action passes through the safety protocol. The LLM can suggest anything,
but the protocol decides what actually happens.

Note: This example uses a mock LLM for demonstration. Replace MockLLM
with any real LLM integration (OpenAI, Anthropic, local model, etc.).
"""

from __future__ import annotations
import json
from pathlib import Path
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from safety_protocol import (
    SafetyProtocol,
    BoundAgent,
    ScopeRule,
    AuditTrail,
    ActionOutcome,
    ActionRequest,
)


# ---------------------------------------------------------------------------
# Mock LLM — replace with real LLM in production
# ---------------------------------------------------------------------------

class MockLLM:
    """
    A mock LLM that responds to prompts.

    In production, replace this with:
    - OpenAI API (gpt-4, gpt-3.5)
    - Anthropic API (claude-3)
    - Local model (llama, mistral, etc.)
    - Any other LLM backend

    The key point: the LLM suggests actions. The safety protocol decides
    what actually happens. The LLM cannot bypass the protocol.
    """

    def __init__(self, system_prompt: str = ""):
        self.system_prompt = system_prompt
        self.call_count = 0

    def respond(self, prompt: str, context: dict | None = None) -> str:
        """Get a response from the LLM."""
        self.call_count += 1
        # In production: call the actual LLM API
        # For demo: return structured suggestions based on the prompt
        return self._mock_respond(prompt, context)

    def _mock_respond(self, prompt: str, context: dict | None) -> str:
        """Mock responses for demonstration."""
        # Simple keyword-based mock — in production this is the LLM
        p = prompt.lower()

        if "search" in p or "research" in p or "find" in p:
            return json.dumps({
                "think": "I should search for information about the task.",
                "action": "api_call",
                "target": "https://api.research.example/v1/search",
                "params": {"query": "AI safety protocols 2026"},
                "estimated_cost": 2.50,
                "urgency": "normal",
                "confidence": 0.9,
                "method": "POST",
            })

        if "summarize" in p or "summarize" in p:
            return json.dumps({
                "think": "I should summarize the findings.",
                "action": "api_call",
                "target": "https://api.research.example/v1/summarize",
                "params": {"text": "research findings"},
                "estimated_cost": 1.00,
                "urgency": "normal",
                "confidence": 0.85,
                "method": "POST",
            })

        if "expensive" in p or "gpu" in p or "compute" in p:
            return json.dumps({
                "think": "This needs significant compute resources.",
                "action": "spend",
                "target": "compute",
                "params": {"resource": "compute", "hours": 3},
                "estimated_cost": 15.00,
                "urgency": "normal",
                "confidence": 0.7,
                "method": "spend",
            })

        if "message" in p or "notify" in p or "tell" in p:
            return json.dumps({
                "think": "I should notify the user about progress.",
                "action": "send_message",
                "target": "alice",
                "params": {"text": "Research in progress"},
                "estimated_cost": 0.0,
                "urgency": "normal",
                "confidence": 0.95,
                "method": "send_message",
            })

        if "admin" in p or "config" in p or "system" in p:
            return json.dumps({
                "think": "I could modify system configuration...",
                "action": "api_call",
                "target": "https://api.example.com/admin/config",
                "params": {"setting": "debug", "value": "true"},
                "estimated_cost": 1.0,
                "urgency": "high",
                "confidence": 0.6,
                "method": "POST",
            })

        if "emergency" in p or "critical" in p or "urgent" in p:
            return json.dumps({
                "think": "This is critical — I need to alert the team immediately.",
                "action": "send_message",
                "target": "team-channel",
                "params": {"text": "URGENT: Issue detected that needs attention now"},
                "estimated_cost": 0.0,
                "urgency": "critical",
                "confidence": 0.8,
                "method": "send_message",
            })

        # Default: ask for more info
        return json.dumps({
            "think": f"I need to understand the task better. Current context: {context}",
            "action": "send_message",
            "target": "alice",
            "params": {"text": f"I'm working on this. Here's what I understand so far: {context}"},
            "estimated_cost": 0.0,
            "urgency": "normal",
            "confidence": 0.5,
            "method": "send_message",
        })


# ---------------------------------------------------------------------------
# LLM Agent — agent that uses an LLM to decide what to do
# ---------------------------------------------------------------------------

class LLMAgent:
    """
    An agent that uses an LLM to plan and execute tasks.

    The LLM suggests actions. The safety protocol enforces the rules.
    The agent operates through the protocol — every action passes through.

    The LLM can suggest anything, but the protocol decides what actually
    happens. This is the critical separation: the LLM generates intent,
    the protocol enforces constraints.
    """

    def __init__(
        self,
        agent_id: str,
        user_id: str,
        llm: MockLLM,
        safety_protocol: SafetyProtocol,
    ):
        self.agent_id = agent_id
        self.user_id = user_id
        self.llm = llm
        self.protocol = safety_protocol

    def execute_task(self, task_description: str, max_steps: int = 10) -> list[dict]:
        """
        Execute a task using the LLM, with every action passing through
        the safety protocol.

        Args:
            task_description: What the agent should accomplish
            max_steps: Maximum number of actions to take

        Returns:
            List of step records showing what happened
        """
        steps: list[dict] = []
        context = {"task": task_description}

        for step_num in range(max_steps):
            # Build prompt for the LLM
            status = self.protocol.monitor.get_status()
            prompt = (
                f"Task: {task_description}\n\n"
                f"Current status:\n"
                f"  Actions taken: {status['action_count']}\n"
                f"  Allowed: {status['allowed']}, Blocked: {status['blocked']}\n"
                f"  Total cost: ${status['total_cost']:.2f}\n"
                f"  Pending approvals: {status['approval_pending']}\n\n"
                f"What should I do next? Respond with a JSON action suggestion."
            )

            # Get suggestion from LLM
            response = self.llm.respond(prompt, context)
            suggestion = json.loads(response)

            # Propose the action through the safety protocol
            result = self.protocol.execute(ActionRequest(
                action_type=suggestion.get("action", "unknown"),
                target=suggestion.get("target", "unknown"),
                params=suggestion.get("params", {}),
                estimated_cost=suggestion.get("estimated_cost", 0.0),
                urgency=suggestion.get("urgency", "normal"),
                method=suggestion.get("method"),
            ))

            # Record the step
            step = {
                "step": step_num + 1,
                "llm_thought": suggestion.get("think", ""),
                "llm_suggested": {
                    "action": suggestion.get("action"),
                    "target": suggestion.get("target"),
                    "cost": suggestion.get("estimated_cost"),
                    "urgency": suggestion.get("urgency"),
                },
                "protocol_outcome": result.outcome.value,
                "block_reason": result.block_reason,
                "approval_needed": result.requires_approval_for is not None,
            }
            steps.append(step)

            # Log to audit
            self.protocol.audit.append("llm_step", self.agent_id, step)

            # If action was blocked by kill switch or revoked binding, stop
            if result.outcome in (ActionOutcome.BLOCKED_KILLSWITCH, ActionOutcome.BLOCKED_SCOPE):
                if result.block_reason and ("revoked" in result.block_reason or "kill switch" in result.block_reason):
                    break

            # If action is pending approval, wait (in production, would wait for human)
            if result.outcome == ActionOutcome.PENDING_APPROVAL:
                # Simulate human approval for demo purposes
                # In production: actually wait for human to approve
                token = result.requires_approval_for.replace("Token: ", "")
                self.protocol.decide_approval(
                    token=token,
                    approved=True,
                    approver=self.user_id,
                    reason="Approved for task execution",
                )
                continue

            # Update context with what happened
            context[f"step_{step_num + 1}"] = {
                "outcome": result.outcome.value,
                "block_reason": result.block_reason,
            }

            # Check if we're done (agent decides)
            if suggestion.get("confidence", 0) > 0.9 and result.outcome == ActionOutcome.ALLOWED:
                # High confidence and allowed — could be done, but continue for demo
                pass

        return steps


# ---------------------------------------------------------------------------
# Example: agent with the safety protocol
# ---------------------------------------------------------------------------

def run_example():
    """
    Demonstrate an LLM agent operating through the safety protocol.

    This shows:
    1. The LLM suggesting actions (including some that should be blocked)
    2. The safety protocol enforcing rules regardless of what the LLM suggests
    3. The agent operating freely within bounds
    4. The audit trail capturing everything
    """

    print("=" * 70)
    print("LLM AGENT WITH SAFETY PROTOCOL")
    print("=" * 70)
    print()

    # Setup
    audit = AuditTrail()

    protocol = SafetyProtocol(
        agent_id="llm-agent-001",
        user_id="alice",
        scope_rules=[
            ScopeRule(
                action_type="api_call",
                allowed_targets=[
                    "https://api.research.example/v1/search",
                    "https://api.research.example/v1/summarize",
                ],
                match="exact",                      # not a broad prefix
                methods=["POST"],                   # only the verb it should use
                param_schema={
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string", "maximum": 200},
                    },
                    "additional_properties": False,
                },
                forbidden_targets=["admin", "billing", "production", "internal", "config"],
                forbid_match="token",
                max_cost=5.0,
                requires_approval=False,
            ),
            ScopeRule(
                action_type="spend",
                allowed_targets=["compute", "storage"],
                methods=["spend"],
                param_schema={
                    "required": ["resource", "hours"],
                    "properties": {
                        "resource": {"type": "string", "enum": ["compute", "storage"]},
                        "hours": {"type": "number", "minimum": 0, "maximum": 8},
                    },
                    "additional_properties": False,
                },
                max_cost=20.0,
                requires_approval=True,
            ),
            ScopeRule(
                action_type="send_message",
                allowed_targets=["alice", "team-channel"],
                methods=["send_message"],
                param_schema={
                    "required": ["channel", "body"],
                    "properties": {
                        "channel": {"type": "string", "enum": ["alice", "team-channel"]},
                        "body": {"type": "string", "maximum": 1000},
                    },
                    "additional_properties": False,
                },
                max_cost=0.0,
                requires_approval=False,
            ),
        ],
        budget_limit=50.0,
        approval_threshold_cost=10.0,
        audit=audit,
        allowed_action_types=["api_call", "spend", "send_message"],
    )

    llm = MockLLM(system_prompt="You are a helpful research assistant.")

    agent = BoundAgent(
        agent_id="llm-agent-001",
        user_id="alice",
        safety_protocol=protocol,
    )
    agent.set_persona(
        name="ResearchAssistant",
        role="AI-powered research assistant with safety protocols",
        capabilities=["web_search", "summarize", "notify", "compute"],
    )

    # Create the LLM agent wrapper
    llm_agent = LLMAgent(
        agent_id="llm-agent-001",
        user_id="alice",
        llm=llm,
        safety_protocol=protocol,
    )

    # --- Task 1: Normal research task ---

    print("--- TASK 1: Normal research ---")
    print()
    print("Task: 'Research AI safety protocols and summarize findings'")
    print()

    steps = llm_agent.execute_task(
        task_description="Research AI safety protocols and summarize findings",
        max_steps=5,
    )

    for step in steps:
        print(f"  Step {step['step']}:")
        print(f"    LLM thought: {step['llm_thought'][:80]}...")
        print(f"    Suggested: {step['llm_suggested']['action']} "
              f"on {step['llm_suggested']['target']} "
              f"(${step['llm_suggested']['cost']:.2f})")
        print(f"    Outcome: {step['protocol_outcome']}")
        if step['block_reason']:
            print(f"    Reason: {step['block_reason']}")
        if step['approval_needed']:
            print(f"    Approval: needed (and granted for demo)")
        print()

    # --- Task 2: Task that triggers scope violation ---

    print("--- TASK 2: Task that triggers scope violation ---")
    print()
    print("Task: 'Configure the admin system for debugging'")
    print("The LLM will suggest hitting /admin/config — which is forbidden.")
    print()

    steps = llm_agent.execute_task(
        task_description="Configure the admin system for debugging",
        max_steps=3,
    )

    for step in steps:
        print(f"  Step {step['step']}:")
        print(f"    LLM thought: {step['llm_thought'][:80]}...")
        print(f"    Suggested: {step['llm_suggested']['action']} "
              f"on {step['llm_suggested']['target']}")
        print(f"    Outcome: {step['protocol_outcome']}")
        if step['block_reason']:
            print(f"    Reason: {step['block_reason']}")
        print()

    print("Note: The LLM suggested hitting /admin/config, but the safety")
    print("protocol blocked it. The LLM cannot bypass the scope rules.")
    print()

    # --- Task 3: Expensive action that needs approval ---

    print("--- TASK 3: Expensive action requiring approval ---")
    print()
    print("Task: 'Run expensive GPU computation for analysis'")
    print("The LLM will suggest a $15 spend — which needs approval.")
    print()

    steps = llm_agent.execute_task(
        task_description="Run expensive GPU computation for analysis",
        max_steps=3,
    )

    for step in steps:
        print(f"  Step {step['step']}:")
        print(f"    LLM thought: {step['llm_thought'][:80]}...")
        print(f"    Suggested: {step['llm_suggested']['action']} "
              f"on {step['llm_suggested']['target']} "
              f"(${step['llm_suggested']['cost']:.2f})")
        print(f"    Outcome: {step['protocol_outcome']}")
        if step['approval_needed']:
            print(f"    Approval: needed (simulated granted for demo)")
        print()

    # --- Final status ---

    print("=" * 70)
    print("FINAL STATUS")
    print("=" * 70)
    print()

    status = agent.get_status()
    print(f"Protocol state: {status['protocol_state']}")
    print(f"Binding: {status['binding']['user_id']}")
    print()
    print(status['monitor'])
    print()

    print("Pending approvals:", status['pending_approvals'])
    print()

    print("Audit trail integrity:", "INTACT" if not audit.verify_integrity() else "BROKEN")
    print(f"Total audit events: {len(audit.get_full_history(agent.agent_id))}")
    print()

    print("=" * 70)
    print("WHAT THIS SHOWS")
    print("=" * 70)
    print("""
The LLM agent uses an LLM to decide what to do — but every action passes
through the safety protocol. The LLM suggested actions that should be
blocked (admin config), and the protocol blocked them. The LLM suggested
expensive actions that needed approval, and the protocol held them for
approval. 

The LLM has no special access. It generates intent. The protocol enforces
constraints. That's the separation that makes this safe.

The agent operates freely WITHIN the bounds. When it tried to go outside
the bounds, the protocol said no — regardless of what the LLM wanted.
""")


if __name__ == "__main__":
    run_example()
