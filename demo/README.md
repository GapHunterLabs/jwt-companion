# Demo tokens

All tokens below are real, correctly-signed JWTs generated with a
throwaway script for this repo — never a real credential, and
regeneratable at any time. None of the keys/secrets here are used
anywhere else.

- `tokens/valid-hs256.txt` + `tokens/valid-hs256-secret.txt` — a valid
  HS256 token and the shared secret it was signed with. Verifying it in
  the tool window with this secret should report "Signature is valid."
- `tokens/expired-rs256.txt` + `tokens/expired-rs256-public-key.pem` — an
  RS256 token whose `exp` claim is in the past. Decoding it shows the
  EXPIRED indicator on the `exp` claim; verifying with the paired public
  key should still report "Signature is valid" (an expired token can
  still have a genuinely valid signature — the two checks are
  independent).
- `tokens/many-claims.txt` — an unsigned (`alg: none`) token with 17
  claims, used to demonstrate the tool window's scrollable claims panels
  instead of a fixed-row table (the direct fix for the competitor
  complaint this plugin exists to address — see the main README's "Why
  it exists" section).

## Regenerating these vectors

The generator script that produced these tokens lives outside this repo
(a throwaway `.java` file used once during development, not checked in
here since it has no ongoing purpose). To regenerate equivalent vectors
from scratch: standard `javax.crypto.Mac`/`java.security.Signature` calls
with `HmacSHA256`/`SHA256withRSA`, signing `base64url(header) + "." +
base64url(payload)` per RFC 7515 §5.1 — the same logic
`JwtVerifier.kt`/`JwtDecoder.kt` implement for verification.
