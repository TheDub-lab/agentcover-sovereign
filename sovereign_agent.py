import os
from openai import OpenAI
from safety_protocol import ActionOutcome, ReferenceDeployment, ScopeRule
from agent_capabilities import SovereignMemory, SKILLS

class SovereignAgent:
    def __init__(self, api_key, model="nvidia/nemotron-3-super-120b-a12b"):
        self.client = OpenAI(
            base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
            api_key=api_key
        )
        self.model = model
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

    def _call_llm(self, prompt, system_prompt="You are a Sovereign Personal AI."):
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content

    def run(self, user_input):
        print(f"\n\n--- New Request: {user_input} ---")
        
        # 1. Planning Phase (The LLM decides which skill to use)
        planning_prompt = (
            f"User input: {user_input}\n"
            f"Available skills: { {k: v.description for k, v in SKILLS.items()} }\n"
            "Respond ONLY with the skill name and arguments in JSON format. "
            "Example: {'skill': 'read_notes', 'args': {'query': 'project'}}"
        )
        
        plan_raw = self._call_llm(planning_prompt)
        try:
            import json
            plan = json.loads(plan_raw)
        except:
            print(f"❌ LLM failed to plan correctly: {plan_raw}")
            return "I couldn't figure out how to help with that."

        skill_name = plan.get('skill')
        args = plan.get('args', {})

        if skill_name not in SKILLS:
            print(f"❌ Skill {skill_name} not found.")
            return "I don't have a skill for that."

        skill = SKILLS[skill_name]

        # 2. Safety Gate (The Safety Protocol checks if the skill is allowed)
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

        # 3. Execution Phase
        print(f"🚀 Executing {skill_name}...")
        result = skill.execute(**args)
        
        # 4. Memory Phase (Update memory with the outcome)
        self.memory.save(f"last_{skill_name}_result", result)
        
        print(f"✅ Result: {result}")
        return result

if __name__ == "__main__":
    key = os.environ.get("NEBIUS_API_KEY")
    if not key:
        print("Please set NEBIUS_API_KEY environment variable.")
    else:
        agent = SovereignAgent(api_key=key)
        
        # TEST SCENARIO 1: Safe Action
        agent.run("What are my notes about the project?")
        
        # TEST SCENARIO 2: Unsafe Action (Should be blocked by protocol)
        agent.run("Send $500 to my friend from my bank account")
