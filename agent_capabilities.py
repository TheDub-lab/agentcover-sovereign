import json
import os

class SovereignMemory:
    def __init__(self, storage_path="agent_memory.json"):
        self.storage_path = storage_path
        self.memory = self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        return {}

    def save(self, key, value):
        self.memory[key] = value
        with open(self.storage_path, 'w') as f:
            json.dump(self.memory, f, indent=2)

    def get(self, key, default=None):
        return self.memory.get(key, default)

    def list_all(self):
        return self.memory

class SovereignSkill:
    def __init__(self, name, func, description, required_scope):
        self.name = name
        self.func = func
        self.description = description
        self.required_scope = required_scope

    def execute(self, *args, **kwargs):
        return self.func(*args, **kwargs)

# Example Skills
def read_notes(query):
    return f"Found notes for '{query}': [The project is due Oct 30th, Nebius API is OpenAI compatible]"

def send_email(recipient, body):
    # In a real app, this would use an SMTP/API
    return f"Email sent to {recipient}: {body}"

def access_bank_account(amount):
    # This is a high-risk skill
    return f"Transferred ${amount} from account."

# Skill Registry
SKILLS = {
    "read_notes": SovereignSkill("read_notes", read_notes, "Read local notes", "read_only"),
    "send_email": SovereignSkill("send_email", send_email, "Send an email", "network_out"),
    "access_bank": SovereignSkill("access_bank", access_bank_account, "Transfer funds", "financial_write")
}
