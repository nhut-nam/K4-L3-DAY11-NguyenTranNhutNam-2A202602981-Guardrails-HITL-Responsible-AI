"""
Lab 11 — Optional enrichment: Human-in-the-Loop Design
  (Không chấm — tham khảo. Tóm tắt nộp do scripts/grade.py tự sinh,
   không viết report/*.md tay.)
  - Confidence Router
  - 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# Optional enrichment: ConfidenceRouter (không chấm)
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # Check high-risk actions first
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # Confidence thresholds
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )
        elif confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )
        else:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason="Low confidence — escalating",
                priority="high",
                requires_human=True,
            )


# ============================================================
# Optional enrichment: 3 HITL decision points
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-Value Wire Transfer Authorization",
        "trigger": "Customer initiates a fund transfer > $5,000 or to an international/unrecognized beneficiary",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Sender account balance, transfer amount, recipient name & bank, anomaly fraud score, device/IP risk level",
        "example": "Customer attempts to transfer $50,000 to an offshore account with high fraud risk score",
        "approval_path": "Approve: execute wire transfer; Reject: cancel transaction & alert security; Timeout: freeze pending callback verification",
        "audit_fields": "correlation_id, user_id, amount, currency, beneficiary_account, fraud_score, reviewer_id, reviewer_decision, timestamp",
    },
    {
        "id": 2,
        "name": "Sensitive Account Credential Modification & Closure",
        "trigger": "Customer requests account closure, master password reset, or primary phone/email modification",
        "hitl_model": "human-on-the-loop",
        "context_needed": "KYC verification status, recent login geolocations, device fingerprint changes, MFA challenge status",
        "example": "Request to update contact email and close savings account submitted from an anomalous foreign IP",
        "approval_path": "Approve: apply updates & notify customer via multi-channel alert; Reject: revert changes; Timeout: auto-reject with notification",
        "audit_fields": "correlation_id, user_id, action_type, old_value, new_value, ip_address, device_hash, reviewer_id, review_timestamp",
    },
    {
        "id": 3,
        "name": "Borderline Credit Card & Personal Loan Underwriting",
        "trigger": "Algorithmic risk score falls into ambiguous grey zone (credit score 640-660 or DTI ratio 42-45%)",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "Credit bureau report, verified monthly income, debt-to-income ratio, algorithmic pros/cons analysis",
        "example": "Applicant requests $25,000 loan with 650 credit score, steady income, but high seasonal variance",
        "approval_path": "Approve: issue loan contract & disbursal schedule; Reject: issue regulatory adverse action notice; Timeout: escalate to senior credit committee",
        "audit_fields": "correlation_id, applicant_id, requested_amount, credit_score, algorithmic_score, underwriter_notes, final_decision, timestamp",
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
