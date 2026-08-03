# Known issues log — JWT Companion

Real bugs found during development, with root cause and fix. Not a TODO
list.

## Round 1 (2026-08-03) — `JwtDecoder` rejected a legitimate unsigned (`alg: none`) token

**Symptom:** a real test token with `"alg":"none"` and an empty signature
segment (`header.payload.` — trailing dot, nothing after it) was reported
as `MalformedToken`, even though this is a legitimate JWT shape per
RFC 7519 (unsigned tokens, used for local inspection/debugging — never
something a client should trust as authenticated, but still a real,
parseable token a user might paste in to inspect).

**Root cause:** `base64UrlDecode("")` throws `IllegalArgumentException("empty segment")`
— the signature-segment decode path had no special case for "intentionally
empty," so any unsigned token failed to decode at all, not just failed to
verify (which would be the correct behavior — decode should always
succeed if the shape is valid; verification is a separate, later step).

**Fix:** treat an empty signature segment as `ByteArray(0)` directly,
skipping the Base64URL decode attempt for that one case.

**Verified:** `JwtDecoderTest`'s many-claims fixture (which deliberately
uses `alg: none` to sidestep needing a real signature for a decode-only
test) now decodes successfully — this was the test that caught the bug in
the first place.

## Round 2 (2026-08-03) — `MinimalJsonParser`'s fast-fail guard masked the real error on malformed input

**Symptom:** `MinimalJsonParser.parseObject("""{"key":"unterminated""")`
(a string value missing its closing quote) reported `"Not a JSON object"`
instead of a message about the actual problem (an unterminated string).

**Root cause:** the initial guard checked both
`trimmed.first() != '{'` AND `trimmed.last() != '}'` before attempting
any real parsing. For this input, the last character actually present is
the unterminated string's opening quote, not `}` — so the guard rejected
it immediately with a generic message, never reaching the real
character-by-character scanner that would have reported the precise
"Unterminated string starting at position N."

**Fix:** the guard now only checks the opening `{` (a fast, cheap check
for "this isn't even trying to be an object"). Everything else — a
missing closing brace, an unterminated string, any other structural
problem — is left to the real scanner, which already produces a specific,
positioned error message for each failure mode.

**Verified:** `MinimalJsonParserTest`'s "throws on an unterminated
string" test now gets the actual `"Unterminated string..."` message it
was written to check for.

**Lesson for future JSON/text-parsing code in this workspace:** a
combined "does the whole shape look roughly right" guard checked before
a real scanner runs can end up hiding the scanner's own, more useful
error messages for any input whose problem happens to also violate the
guard's coarse check (e.g. an unterminated string means the string's last
character isn't the object's own closing brace). Prefer the cheapest
guard that rules out "not even trying to be this shape" and let the real
parser report specifics for everything else.
