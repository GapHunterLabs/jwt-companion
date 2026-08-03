# JWT Companion

IntelliJ-family plugin. Decode and verify JSON Web Tokens directly in a
dedicated tool window — no browser round-trip, no data leaving the IDE.

## Why it exists

Born from real evidence in JetBrains Marketplace reviews of JWT (JSON
Web Token) Analyzer (74,353 downloads), not assumptions:

- "Decoded payload represents the table with fixed two rows. So if you
  have a lot of claims this is very inconvenient to scroll the content
  to analyze it." — a real-world token with more than a couple of claims
  becomes unreadable in the incumbent's UI.
- "Unsupported algorithm RS256 | Can you please add the support? It
  would have been 5 stars feedback, if it was supported." — RS256 is one
  of the most common signing algorithms in production OAuth/OIDC setups,
  and the incumbent doesn't support verifying it.

## Why built this way

- **Two independently scrollable panels (Header, Payload), never a
  fixed-height table.** Each claim is its own row in a vertically
  scrolling panel — a 20-claim token is exactly as usable as a 2-claim
  one. This is the direct, structural fix for the "fixed two rows...
  very inconvenient to scroll" complaint, verified by an automated test
  (`JwtDecoderPanelTest`) that decodes a real 17-claim token and asserts
  every claim gets its own row — not just eyeballed once in a running
  IDE.
- **RS256 signature verification, alongside HS256** — both implemented
  with only the JDK's own `javax.crypto`/`java.security` APIs (same
  JDK-only philosophy as Cert Companion's certificate parsing), verified
  against real, independently-generated test vectors: a genuine RSA
  keypair signs a token, and the test suite confirms verification
  succeeds with the correct public key and fails with an unrelated one —
  not just "compiles and looks plausible."
- **A hand-rolled, minimal JSON object parser instead of a new
  dependency** — same call already made elsewhere in this workspace
  (Ansible Companion's bundled module index, API Security Companion's
  OpenAPI checks): no JSON/YAML library ships on the platform's core
  classpath, and a JWT header/payload is always a single, mostly-flat
  JSON object, not a document that needs a general-purpose parser.
- **Constant-time signature comparison** (`MessageDigest.isEqual`, not
  `contentEquals`) for HS256 — a naive byte-array comparison short-
  circuits on the first mismatching byte, a textbook timing side-channel
  for signature checks.
- **Nothing is ever persisted.** The token, HS256 secret, and RS256 key
  you type or paste live in memory only, cleared the moment the tool
  window is closed or the token field is cleared.

## Usage

Open the **JWT Companion** tool window (right side of the IDE) → paste a
token → **Decode**. Header and payload claims appear in their own tabs,
each independently scrollable. `iat`/`exp`/`nbf` are shown as
human-readable UTC dates with an EXPIRED/EXPIRING_SOON/NOT_YET_VALID/
VALID indicator. To verify the signature, enter the shared secret (HS256)
or paste a public key/certificate PEM (RS256) in the panel below and
click the matching **Verify** button.

## Enterprise / Team Licensing

Need enterprise features, support for additional algorithms, or team
licensing? Contact us at **kennyj.diazm@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

`demo/tokens/` has real, signed test tokens (see `demo/README.md`) used
by both the automated test suite and for manual inspection if wanted —
no network access or external service needed to try any of this.

## License

Apache-2.0. See `LICENSE`.
