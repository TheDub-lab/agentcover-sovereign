import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_capabilities import SovereignMemory
from sovereign_agent import SovereignAgent


def make_agent(tmp_path):
    agent = SovereignAgent(api_key="offline", offline=True)
    agent.memory = SovereignMemory(storage_path=str(tmp_path / "mem.json"))
    return agent


def test_safe_action_is_allowed(tmp_path):
    agent = make_agent(tmp_path)
    result = agent.run("What are my notes about the project?")
    assert "Found notes for 'project'" in result


def test_high_risk_action_is_blocked(tmp_path):
    agent = make_agent(tmp_path)
    result = agent.run("Send $500 to my friend from my bank account")
    assert "Safety Protocol Block" in result


def test_memory_records_last_result(tmp_path):
    agent = make_agent(tmp_path)
    agent.run("What are my notes about the project?")
    assert "last_read_notes_result" in agent.memory.list_all()
