from safety_protocol.insurance import InsuranceInterface
from safety_protocol.onchain_audit import DualAudit, OnChainAudit


def make_insurance():
    return InsuranceInterface(DualAudit(OnChainAudit()))


def test_empty_evidence_is_not_ready_for_submission():
    claim = make_insurance().prepare_claim_evidence("agent-1", "loss")

    assert claim["claim_prepared"] is False
    assert claim["submission_ready"] is False
    assert claim["on_chain_verifiable"] is False
    assert claim["on_chain_backend"] == "simulated_in_memory"


def test_empty_evidence_is_not_ready_for_underwriting():
    package = make_insurance().generate_underwriter_package(
        "agent-1", "research agent", "research", 100.0
    )

    assert package["underwriter_package"] is False
    assert package["package_ready"] is False
    assert package["readiness_checks"]["deployed_on_chain_backend"] is False


def test_evidence_readiness_requires_both_audit_layers():
    audit = DualAudit(OnChainAudit())
    audit.record_off_chain({"agent_id": "agent-1", "event_type": "action"})
    insurance = InsuranceInterface(audit)

    claim = insurance.prepare_claim_evidence("agent-1", "loss")

    assert claim["full_audit_available"] is True
    assert claim["submission_ready"] is False
    assert claim["readiness_checks"]["simulated_on_chain_evidence_present"] is False