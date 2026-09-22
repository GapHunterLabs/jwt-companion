# JWT Companion

IntelliJ-family plugin. Decode and verify JSON Web Tokens directly in a
dedicated tool window — no browser round-trip, no data leaving the IDE.

## Why it exists

JWT decoding in the IDE is not a new idea -- the long-standing option is
JWT (JSON Web Token) Analyzer (75,144 downloads, free). Two things led to
this plugin, checked again in September 2026:

- **Algorithm coverage.** The incumbent verifies HS256, HS384 and RS256.
  This plugin verifies all twelve JWS algorithms the JDK implements:
  HS256/384/512, RS256/384/512, PS256/384/512 and ES256/384/512. ECDSA
  (the `ES*` family, used by most OIDC providers that moved off RSA) and
  RSA-PSS are the practical gaps.
- **A token with many claims stays readable.** Header and payload each get
  their own scrolling panel with one row per claim, checked by an
  automated test (`JwtDecoderPanelTest`) that decodes a real 17-claim
  token and asserts every claim gets a row.

What the incumbent has and this plugin does not: editing claim values, a
default keypair stored in Preferences, and relative-time rendering. If
those matter more than algorithm coverage, it is the better tool.

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
or paste a public key/certificate PEM (`RS*`, `PS*`, `ES*`) in the panel
below and click **Verify** -- the token's own `alg` header decides which
of the two inputs is used.

## Enterprise / Team Licensing

Need enterprise features or team licensing? Contact us at **gaphunterlabs@gmail.com**.

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
