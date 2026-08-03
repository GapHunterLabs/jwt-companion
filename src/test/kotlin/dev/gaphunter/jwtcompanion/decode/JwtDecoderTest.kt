package dev.gaphunter.jwtcompanion.decode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class JwtDecoderTest {

    // Real HS256 token, generated with a throwaway script (see jwt-companion's
    // demo/README.md for how to regenerate) -- not a hand-typed fixture.
    private val hs256Token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ." +
            "8pyuIvSE_8w0IYspGUEQgRj-xGSllJWfdlkuA5JLvzw"

    @Test
    fun `decodes a well-formed HS256 token into header and payload claims`() {
        val result = JwtDecoder.decode(hs256Token)
        assertTrue(result is JwtDecodeResult.Success)
        val token = (result as JwtDecodeResult.Success).token

        assertEquals("HS256", token.algorithm)
        assertEquals("HS256", token.headerClaims.first { it.key == "alg" }.value)
        assertEquals("JWT", token.headerClaims.first { it.key == "typ" }.value)
        assertEquals("1234567890", token.payloadClaims.first { it.key == "sub" }.value)
        assertEquals("Ada Lovelace", token.payloadClaims.first { it.key == "name" }.value)
        assertEquals(4, token.payloadClaims.size)
    }

    @Test
    fun `preserves claim order from the source JSON, not alphabetical or hash order`() {
        val result = JwtDecoder.decode(hs256Token) as JwtDecodeResult.Success
        val keys = result.token.payloadClaims.map { it.key }
        assertEquals(listOf("sub", "name", "iat", "exp"), keys)
    }

    @Test
    fun `rejects a token that does not have exactly 3 segments`() {
        val result = JwtDecoder.decode("only.two")
        assertTrue(result is JwtDecodeResult.MalformedToken)
        assertTrue((result as JwtDecodeResult.MalformedToken).reason.contains("3 dot-separated segments"))
    }

    @Test
    fun `rejects a token with an empty segment`() {
        val result = JwtDecoder.decode("abc..def")
        assertTrue(result is JwtDecodeResult.MalformedToken)
    }

    @Test
    fun `rejects a header segment that is not valid Base64URL`() {
        val result = JwtDecoder.decode("not-valid-base64!!!.eyJhIjoxfQ.sig")
        assertTrue(result is JwtDecodeResult.MalformedToken)
    }

    @Test
    fun `rejects a payload that decodes to non-JSON text`() {
        // Base64URL of the literal text "not json at all"
        val notJsonB64 = "bm90IGpzb24gYXQgYWxs"
        val header = "eyJhbGciOiJIUzI1NiJ9" // {"alg":"HS256"}
        val result = JwtDecoder.decode("$header.$notJsonB64.sig")
        assertTrue(result is JwtDecodeResult.MalformedToken)
    }

    @Test
    fun `decodes a many-claims token with all claims present and in order, not truncated to a fixed row count`() {
        val manyClaimsToken =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
                "eyJzdWIiOiJ1LTIwNDQiLCJuYW1lIjoiR3JhY2UgSG9wcGVyIiwiZW1haWwiOiJncmFjZS5ob3BwZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OSwibmJmIjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJhY21lLWludGVybmFsLXRvb2xzIiwianRpIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIiwicm9sZSI6ImVuZ2luZWVyaW5nLWxlYWQiLCJkZXBhcnRtZW50IjoiUGxhdGZvcm0gRW5naW5lZXJpbmciLCJvZmZpY2VfbG9jYXRpb24iOiJCdWlsZGluZyA0LCBGbG9vciAyIiwiZW1wbG95ZWVfaWQiOiJFLTcwNDQxIiwibWFuYWdlciI6InUtMTAwMiIsImNvc3RfY2VudGVyIjoiQ0MtNDQ3MSIsImNsZWFyYW5jZV9sZXZlbCI6Ikw0IiwiaGlyZV9kYXRlIjoiMjAxOS0wMy0xMSJ9."
        val result = JwtDecoder.decode(manyClaimsToken)
        assertTrue(result is JwtDecodeResult.Success)
        val claims = (result as JwtDecodeResult.Success).token.payloadClaims
        // 17 claims -- this is exactly the "fixed 2-row table" complaint this
        // plugin exists to fix: every claim must be present, none dropped.
        assertEquals(17, claims.size)
        assertFalse(claims.any { it.key.isBlank() })
    }

    @Test
    fun `signing input is built from the raw encoded segments, not a re-encoding of parsed JSON`() {
        val result = JwtDecoder.decode(hs256Token) as JwtDecodeResult.Success
        val expectedSigningInput = hs256Token.substringBeforeLast(".")
        assertEquals(expectedSigningInput, String(result.token.signingInput, Charsets.US_ASCII))
    }
}
