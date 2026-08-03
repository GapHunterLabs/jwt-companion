package dev.gaphunter.jwtcompanion.decode

import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Pure Kotlin, no platform/PSI dependency -- decoding a JWT is a text
 * transform, not something that needs the IDE running to test or use.
 */
object JwtDecoder {

    /**
     * A JWT's three segments are Base64URL (RFC 4648 §5), not standard
     * Base64 -- '-'/'_' instead of '+'/'/', and padding is typically
     * omitted. `Base64.getUrlDecoder()` handles the alphabet but still
     * requires correct padding on some JDK versions' stricter mode, so
     * padding is normalized explicitly before decoding rather than assumed
     * present or absent.
     */
    fun decode(rawToken: String): JwtDecodeResult {
        val token = rawToken.trim()
        val parts = token.split(".")
        if (parts.size != 3) {
            return JwtDecodeResult.MalformedToken(
                "A JWT must have exactly 3 dot-separated segments (header.payload.signature), found ${parts.size}.",
            )
        }
        val (headerPart, payloadPart, signaturePart) = parts

        val headerBytes = try {
            base64UrlDecode(headerPart)
        } catch (e: IllegalArgumentException) {
            return JwtDecodeResult.MalformedToken("Header segment is not valid Base64URL: ${e.message}")
        }
        val payloadBytes = try {
            base64UrlDecode(payloadPart)
        } catch (e: IllegalArgumentException) {
            return JwtDecodeResult.MalformedToken("Payload segment is not valid Base64URL: ${e.message}")
        }
        // An empty signature segment is a legitimate case (alg: "none",
        // RFC 7519 -- unsigned tokens used for local debugging/inspection,
        // never something a client should trust as authenticated) -- decode
        // still succeeds, verification of an unsigned token is simply out
        // of scope (there's nothing to check the signature against).
        val signatureBytes = if (signaturePart.isEmpty()) {
            ByteArray(0)
        } else {
            try {
                base64UrlDecode(signaturePart)
            } catch (e: IllegalArgumentException) {
                return JwtDecodeResult.MalformedToken("Signature segment is not valid Base64URL: ${e.message}")
            }
        }

        val headerJson = String(headerBytes, StandardCharsets.UTF_8)
        val payloadJson = String(payloadBytes, StandardCharsets.UTF_8)

        val headerClaims = try {
            MinimalJsonParser.parseObject(headerJson)
        } catch (e: MinimalJsonParser.JsonParseException) {
            return JwtDecodeResult.MalformedToken("Header is not a valid JSON object: ${e.message}")
        }
        val payloadClaims = try {
            MinimalJsonParser.parseObject(payloadJson)
        } catch (e: MinimalJsonParser.JsonParseException) {
            return JwtDecodeResult.MalformedToken("Payload is not a valid JSON object: ${e.message}")
        }

        val algorithm = headerClaims.firstOrNull { it.key == "alg" }?.value

        // The signing input is the exact original (still-encoded) header and
        // payload segments joined by '.', per RFC 7515 §5.1 -- NOT a
        // re-encoding of the parsed JSON, since re-encoding could produce
        // different bytes (key order, whitespace, escaping) than what was
        // actually signed.
        val signingInput = "$headerPart.$payloadPart".toByteArray(StandardCharsets.US_ASCII)

        return JwtDecodeResult.Success(
            JwtToken(
                headerJson = headerJson,
                payloadJson = payloadJson,
                headerClaims = headerClaims,
                payloadClaims = payloadClaims,
                signatureBytes = signatureBytes,
                signingInput = signingInput,
                algorithm = algorithm,
            ),
        )
    }

    private fun base64UrlDecode(segment: String): ByteArray {
        if (segment.isEmpty()) throw IllegalArgumentException("empty segment")
        val padded = when (segment.length % 4) {
            2 -> "$segment=="
            3 -> "$segment="
            else -> segment
        }
        return Base64.getUrlDecoder().decode(padded)
    }
}
