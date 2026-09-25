<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# JWT Companion Changelog

## [Unreleased]

## [0.2.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.2.0]

### Added

- Verification for every JWS algorithm the JDK implements, not just
  HS256 and RS256: `HS384`/`HS512`, `RS384`/`RS512`, the RSA-PSS family
  (`PS256`/`PS384`/`PS512`) and the ECDSA family
  (`ES256`/`ES384`/`ES512`). Still no bundled crypto library -- all of it
  comes from `javax.crypto`/`java.security`.
- One **Verify** button instead of one per algorithm: the token's own
  `alg` header decides whether the shared secret or the PEM key is used.
- An unsigned token (`alg: none`) is now reported as unsigned, instead of
  as an algorithm that cannot be verified.
- Demo tokens for ES256 and PS256, each with its public key, and a test
  that verifies every demo token against the key stored next to it.

### Fixed

- Pasting an RSA key for an ES256 token (or the reverse) said "invalid
  key spec"; it now names the key type the algorithm needs and the type
  that was actually pasted. A truncated ECDSA signature reports the
  length that was expected.
- The README claimed the long-standing alternative plugin does not verify
  RS256. Its description lists HS256, HS384 and RS256 today, so that
  comparison was out of date and has been rewritten around what this
  plugin actually covers.

## [0.1.3]

### Added

- Review/star CTA: after 5 successful token decodes (never counted for
  a malformed-token result), a one-time notification asks whether to
  rate the plugin on Marketplace, with a permanent "Don't ask again"
  option.

## [0.1.2]

### Fixed

- Tool window no longer shows the generic platform icon in the sidebar —
  the real Gap Hunter Labs mark is now declared via `icon=` on
  `<toolWindow>`.

## [0.1.1]

### Fixed

- Marketplace listing icon not rendering (showed a broken "plugin icon"
  placeholder) — replaced with the same icon already proven to render
  correctly on other Gap Hunter Labs listings.

## [0.1.0]

### Added

- JWT decode/verify tool window: paste or type a token, see header and
  payload claims in two independently scrollable panels — never a
  fixed-height table that becomes unreadable once a token has more than
  a couple of claims.
- Signature verification for `HS256` (shared secret) and `RS256`
  (public key/certificate PEM), using only the JDK's own
  `javax.crypto`/`java.security` APIs — no bundled crypto library.
- `iat`/`exp`/`nbf` claims rendered as human-readable UTC dates, with a
  VALID/EXPIRING_SOON/EXPIRED/NOT_YET_VALID indicator.
- Nothing typed into the tool window (token, secret, key) is persisted
  between sessions — in-memory only.

[Unreleased]: https://github.com/GapHunterLabs/jwt-companion/compare/0.2.1...HEAD
[0.2.1]: https://github.com/GapHunterLabs/jwt-companion/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/GapHunterLabs/jwt-companion/compare/0.1.3...0.2.0
[0.1.3]: https://github.com/GapHunterLabs/jwt-companion/compare/0.1.2...0.1.3
[0.1.2]: https://github.com/GapHunterLabs/jwt-companion/compare/0.1.1...0.1.2
[0.1.1]: https://github.com/GapHunterLabs/jwt-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/jwt-companion/commits/0.1.0
