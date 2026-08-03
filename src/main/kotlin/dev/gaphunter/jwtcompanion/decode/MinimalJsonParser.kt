package dev.gaphunter.jwtcompanion.decode

/**
 * Hand-rolled JSON object parser instead of a new dependency (same call
 * already made in this workspace for ansible-companion's bundled module
 * index and api-security-companion's OpenAPI checks -- no bundled JSON/YAML
 * library ships in the platform's core classpath, only inside specific
 * bundled plugins like Maven, which isn't a dependency worth taking just
 * for this).
 *
 * Scope: a single flat-or-one-level-nested JSON OBJECT (never an array at
 * the top level) -- exactly the shape of a JWT header or payload per
 * RFC 7519. Nested objects/arrays are rendered as their own compact JSON
 * text rather than recursively flattened, which keeps the claim list
 * one-entry-per-top-level-key (matching how real JWT payloads are read:
 * "what are this token's claims," not "what is every leaf value").
 */
object MinimalJsonParser {

    class JsonParseException(message: String) : Exception(message)

    /** Returns claims in source order -- see [Claim]'s own doc comment for why order matters. */
    fun parseObject(json: String): List<Claim> {
        val trimmed = json.trim()
        // Deliberately only checking the OPENING brace here, not also
        // `trimmed.last() != '}'`: that combined check used to reject any
        // malformed input with a generic "Not a JSON object" before the
        // real scanner below ever ran -- including inputs whose actual
        // problem is in the MIDDLE (e.g. an unterminated string), masking
        // the specific, useful error the scanner would otherwise report at
        // the exact failing position. An input that isn't even trying to be
        // an object (doesn't start with '{') is still rejected fast here;
        // everything else is left to the real scanner to diagnose precisely.
        if (trimmed.isEmpty() || trimmed.first() != '{') {
            throw JsonParseException("Not a JSON object")
        }
        val claims = mutableListOf<Claim>()
        var i = skipWhitespace(trimmed, 1)
        if (i < trimmed.length && trimmed[i] == '}') return claims

        while (i < trimmed.length) {
            i = skipWhitespace(trimmed, i)
            if (i >= trimmed.length) throw JsonParseException("Unexpected end of input, expected a quoted key")
            if (trimmed[i] != '"') throw JsonParseException("Expected a quoted key at position $i")
            val (key, afterKey) = parseString(trimmed, i)
            i = skipWhitespace(trimmed, afterKey)
            if (i >= trimmed.length || trimmed[i] != ':') throw JsonParseException("Expected ':' after key '$key'")
            i = skipWhitespace(trimmed, i + 1)
            val (valueText, afterValue) = parseValueText(trimmed, i)
            claims.add(Claim(key, valueText))
            i = skipWhitespace(trimmed, afterValue)
            if (i < trimmed.length && trimmed[i] == ',') {
                i = skipWhitespace(trimmed, i + 1)
                continue
            }
            if (i < trimmed.length && trimmed[i] == '}') break
            throw JsonParseException("Expected ',' or '}' at position $i")
        }
        return claims
    }

    private fun skipWhitespace(s: String, from: Int): Int {
        var i = from
        while (i < s.length && s[i].isWhitespace()) i++
        return i
    }

    /** Returns (unescaped string content, index right after the closing quote). */
    private fun parseString(s: String, start: Int): Pair<String, Int> {
        require(s[start] == '"')
        val sb = StringBuilder()
        var i = start + 1
        while (i < s.length) {
            val c = s[i]
            if (c == '"') return sb.toString() to (i + 1)
            if (c == '\\' && i + 1 < s.length) {
                when (s[i + 1]) {
                    '"' -> { sb.append('"'); i += 2 }
                    '\\' -> { sb.append('\\'); i += 2 }
                    '/' -> { sb.append('/'); i += 2 }
                    'n' -> { sb.append('\n'); i += 2 }
                    't' -> { sb.append('\t'); i += 2 }
                    'r' -> { sb.append('\r'); i += 2 }
                    'b' -> { sb.append('\b'); i += 2 }
                    'u' -> {
                        if (i + 5 < s.length) {
                            val code = s.substring(i + 2, i + 6).toInt(16)
                            sb.append(code.toChar())
                            i += 6
                        } else {
                            throw JsonParseException("Truncated \\u escape at position $i")
                        }
                    }
                    else -> { sb.append(s[i + 1]); i += 2 }
                }
            } else {
                sb.append(c)
                i++
            }
        }
        throw JsonParseException("Unterminated string starting at position $start")
    }

    /**
     * A "value" for display purposes: strings return their unescaped text;
     * objects/arrays return their own compact source text verbatim (not
     * recursively parsed -- see class doc comment); numbers/booleans/null
     * return their literal text.
     */
    private fun parseValueText(s: String, start: Int): Pair<String, Int> {
        return when (s[start]) {
            '"' -> parseString(s, start)
            '{' -> parseBalanced(s, start, '{', '}')
            '[' -> parseBalanced(s, start, '[', ']')
            else -> parseLiteral(s, start)
        }
    }

    /** Consumes a balanced-bracket span (object or array), respecting quoted strings, returns its raw text. */
    private fun parseBalanced(s: String, start: Int, open: Char, close: Char): Pair<String, Int> {
        var depth = 0
        var i = start
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> {
                    val (_, after) = parseString(s, i)
                    i = after
                    continue
                }
                c == open -> depth++
                c == close -> {
                    depth--
                    if (depth == 0) return s.substring(start, i + 1) to (i + 1)
                }
            }
            i++
        }
        throw JsonParseException("Unbalanced '$open' starting at position $start")
    }

    private fun parseLiteral(s: String, start: Int): Pair<String, Int> {
        var i = start
        while (i < s.length && s[i] != ',' && s[i] != '}' && s[i] != ']' && !s[i].isWhitespace()) i++
        if (i == start) throw JsonParseException("Expected a value at position $start")
        return s.substring(start, i) to i
    }
}
