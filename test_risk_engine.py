
import math
from risk_engine import calculate_fused_score, risk_label


def check(name, condition, details=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {name}: {details}")


# Test 1: Low signals should produce low risk.
score, contradiction = calculate_fused_score(
    0.10,
    {"html_risk": 0.10, "identity_risk": 0.10}
)
check(
    "Low-risk calculation",
    math.isclose(score, 0.10, abs_tol=1e-9)
    and contradiction == 0.0,
    f"score={score:.3f}"
)

# Test 2: Contradictory URL and webpage signals.
meta = {
    "html_risk": 0.80,
    "identity_risk": 0.70,
    "password_fields": 1,
    "external_form_actions": 1,
}
score, contradiction = calculate_fused_score(0.20, meta)
check(
    "Contradiction adjustment",
    math.isclose(contradiction, 0.30, abs_tol=1e-9)
    and math.isclose(score, 0.75, abs_tol=1e-9),
    f"contradiction={contradiction:.2f}, score={score:.3f}"
)

# Test 3: Score should never exceed 1.0.
score, _ = calculate_fused_score(
    1.0,
    {
        "html_risk": 1.0,
        "identity_risk": 1.0,
        "password_fields": 1,
        "external_form_actions": 1,
    }
)
check(
    "Maximum score cap",
    score == 1.0,
    f"score={score:.3f}"
)

# Test 4: Risk labels use the intended thresholds.
check("Low-risk label", risk_label(0.20)[1] == "good")
check("Medium-risk label", risk_label(0.50)[1] == "warn")
check("High-risk label", risk_label(0.80)[1] == "bad")

# Test 5: Invalid model inputs should be rejected.
try:
    calculate_fused_score(1.5, {"html_risk": 0.2, "identity_risk": 0.2})
    invalid_input_rejected = False
except ValueError:
    invalid_input_rejected = True

check("Invalid input validation", invalid_input_rejected)

print("\nRisk-engine tests completed.")
