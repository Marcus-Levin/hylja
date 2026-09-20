# Decision 007: Protected egress fails closed

Status: accepted foundation direction.

If policy, vault authorization, or required high-risk egress verification cannot establish a safe release, protected external egress is blocked rather than bypassed. Lower-risk deterministic fallback is allowed only when policy explicitly defines it.
