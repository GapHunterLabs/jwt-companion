package dev.gaphunter.jwtcompanion.verify

import dev.gaphunter.jwtcompanion.decode.JwtDecodeResult
import dev.gaphunter.jwtcompanion.decode.JwtDecoder
import org.junit.Assert.assertEquals
import org.junit.Test

class JwtVerifierTest {

    // All tokens/keys below are real, generated with a throwaway script for
    // this test suite (see jwt-companion/demo/README.md) -- never a real
    // credential, and regeneratable at any time.

    private val hs256Secret = "gap-hunter-labs-demo-secret"
    private val hs256Token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk5fQ." +
            "8pyuIvSE_8w0IYspGUEQgRj-xGSllJWfdlkuA5JLvzw"

    // Same header+signature as hs256Token, but a payload with exp changed by
    // one digit -- the ORIGINAL signature no longer matches this signing
    // input, so this proves tamper detection, not just "matches its own secret."
    private val hs256TokenTampered =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo5OTk5OTk5OTk4fQ." +
            "8pyuIvSE_8w0IYspGUEQgRj-xGSllJWfdlkuA5JLvzw"

    private val rs256Token =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
            "eyJzdWIiOiI5ODc2NTQzMjEwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9." +
            "f3vh1pCAjB2j_1j81BJFooIKh7EtNWw7zjP3-yxkJewukWlxKmFJKJxOr7yfp8udhnoTgoDramcc_6Qu13mVq9RO0PaD7fFobAQtpMn5ltBuXyydS5uqzKzGpBhDD8cpL2K_5RpPwEdJGlgCcbZS2-psTYPNCnWz6FEpU9ziVe-8JuXloHgvhL92rOfkehTmZvtxKbQ5YckQaysLKbHv5__R_Sm71nPh-fpxL7hK1gmJsSgw2teksyh9-W6uCY-f4it7ZSfeJYsJIprfIKANV_lBgwb5tyw1DNtjGskYtLbDRXDYPredz7VFoHHNpsA-E7fKwPoS_bAjlx7RiFfVmQ"

    private val rs256PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Moiaem+I8b/6igJ6fUS
        IJYcsQfET099FF1LPfQgMGofls+WN37onH6JOuvU9rNfYgG/loA7/UR08Ocafad3
        n8X+7+2HS6ZK1LLLYg0L8yqLMryKFqsYfL+1ThtdVUyeJTH3MHnl3lz0emPYgjO5
        aO9JMAzh6b+cKu8+GTi8t9iKbdmZLXxIjxs2xO2bPa/PvejWJ05OWhH3FT+J6Sja
        YlshX64Rl+XP7bCFpY652FRwpSKYjGLFnsy2tg/Cn3dwOGDxaOykxHtC+fsbP1G6
        PYXpdaTsSc7FturQx/sSiqkNH70VLO7DhWVGG7aAJXH19cDtPeclpwxUE76zoCAk
        QQIDAQAB
        -----END PUBLIC KEY-----
    """.trimIndent()

    // A different, unrelated RSA keypair's public key -- proves verification
    // fails against the WRONG key, not just "any RSA key passes."
    private val wrongPublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzpC6oq+FL+Qe7u0kIj1g
        G9rBW60guKja3wmK41uM68hBTwEi1Fn4oHvX318sBbJgydTfP2k04eUCxDQmSbFW
        WmhU7seeKbinzR8TDS+BK8dZzk47YjBqyrjnoitkl5adbahXjJxQdGlEi6kMJV/b
        uo/52QSWJQ7hyOqgQCLT2kpU+ACRx/p4h6gJfw+e/jbqBlA9pULDdvSOGqLg9NqI
        CPP0pdfHPUSpCtE6sLPCTPbRY16/5iZfv++kwqYESbNa+oL9bGF0u3y/oH1jjjEO
        3Ik0qi7JakjSlDfQXCG652TGhPdPaUm0IkyGLj9qBv681MOjAd+mTVCwR5+ewfrY
        NwIDAQAB
        -----END PUBLIC KEY-----
    """.trimIndent()

    private fun decodeOrFail(token: String) = (JwtDecoder.decode(token) as JwtDecodeResult.Success).token

    @Test
    fun `HS256 verification succeeds with the correct secret`() {
        val result = JwtVerifier.verifyHs256(decodeOrFail(hs256Token), hs256Secret)
        assertEquals(VerificationResult.Valid, result)
    }

    @Test
    fun `HS256 verification fails with the wrong secret`() {
        val result = JwtVerifier.verifyHs256(decodeOrFail(hs256Token), "wrong-secret")
        assertEquals(VerificationResult.InvalidSignature, result)
    }

    @Test
    fun `HS256 verification fails on a tampered payload even with the correct secret`() {
        val result = JwtVerifier.verifyHs256(decodeOrFail(hs256TokenTampered), hs256Secret)
        assertEquals(VerificationResult.InvalidSignature, result)
    }

    @Test
    fun `HS256 verification reports empty secret as a key error, not a false-valid`() {
        val result = JwtVerifier.verifyHs256(decodeOrFail(hs256Token), "")
        assert(result is VerificationResult.KeyParseError)
    }

    @Test
    fun `RS256 verification succeeds with the correct public key PEM`() {
        val result = JwtVerifier.verifyRs256(decodeOrFail(rs256Token), rs256PublicKeyPem)
        assertEquals(VerificationResult.Valid, result)
    }

    @Test
    fun `RS256 verification fails with an unrelated public key`() {
        val result = JwtVerifier.verifyRs256(decodeOrFail(rs256Token), wrongPublicKeyPem)
        assertEquals(VerificationResult.InvalidSignature, result)
    }

    @Test
    fun `RS256 verification reports malformed PEM as a key error`() {
        val result = JwtVerifier.verifyRs256(decodeOrFail(rs256Token), "not a pem block at all")
        assert(result is VerificationResult.KeyParseError)
    }

    @Test
    fun `verifyHs256 reports unsupported algorithm when the token's alg is not HS256`() {
        val result = JwtVerifier.verifyHs256(decodeOrFail(rs256Token), "irrelevant")
        assertEquals(VerificationResult.UnsupportedAlgorithm("RS256"), result)
    }

    @Test
    fun `verifyRs256 reports unsupported algorithm when the token's alg is not RS256`() {
        val result = JwtVerifier.verifyRs256(decodeOrFail(hs256Token), rs256PublicKeyPem)
        assertEquals(VerificationResult.UnsupportedAlgorithm("HS256"), result)
    }
}
