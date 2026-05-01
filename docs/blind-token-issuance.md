# Blind Token Issuance

Blind-token issuance is out of MVP as a privacy mechanism.

The object names `BlindTokenRequest` and `BlindTokenIssue` may remain for schema compatibility. MVP implementations may skip these objects entirely or create deterministic local placeholders when a workflow needs a ballot credential.

## MVP Rules

- No real blind signatures are required.
- No privacy guarantee is claimed.
- Public validators do not need to decrypt any encrypted payload.
- If token objects are used, they only prevent accidental duplicate local ballots.
- Ballot eligibility may be checked against local voter identity, a local token, or another simple deterministic key available in the current implementation.
