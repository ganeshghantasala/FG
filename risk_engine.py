
def calculate_fused_score(ml_risk, meta):
    """Calculate the combined risk score from normalized signals."""

    def validate_score(value, name):
        value = float(value)
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be between 0 and 1")
        return value

    ml_risk = validate_score(ml_risk, "ml_risk")
    html_risk = validate_score(meta.get("html_risk", 0), "html_risk")
    identity_risk = validate_score(
        meta.get("identity_risk", 0), "identity_risk"
    )

    contradiction = 0.0

    # Low URL risk but high webpage risk.
    if ml_risk < 0.35 and html_risk > 0.55:
        contradiction += 0.18

    # Password collection plus an external form destination.
    if (
        meta.get("password_fields", 0) > 0
        and meta.get("external_form_actions", 0) > 0
    ):
        contradiction += 0.12

    score = min(
        1.0,
        0.55 * ml_risk
        + 0.25 * html_risk
        + 0.20 * identity_risk
        + contradiction,
    )

    return score, contradiction


def risk_label(score):
    """Map the combined score to FakeGuard's existing risk categories."""
    if not 0.0 <= score <= 1.0:
        raise ValueError("score must be between 0 and 1")

    if score >= 0.75:
        return "HIGH RISK — LIKELY PHISHING", "bad"
    elif score >= 0.45:
        return "MEDIUM RISK — REVIEW REQUIRED", "warn"
    else:
        return "LOW RISK — LIKELY LEGITIMATE", "good"
