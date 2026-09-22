package dev.gaphunter.jwtcompanion.verify

import dev.gaphunter.jwtcompanion.decode.JwtDecodeResult
import dev.gaphunter.jwtcompanion.decode.JwtDecoder
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/** The demo tokens a tester is told to paste: each one really verifies with the key next to it. */
class DemoTokensTest {

    private fun read(name: String) = File("demo/tokens/$name").readText().trim()

    private fun verify(tokenFile: String, keyFile: String): VerificationResult {
        val decoded = JwtDecoder.decode(read(tokenFile)) as JwtDecodeResult.Success
        return JwtVerifier.verify(decoded.token, read(keyFile))
    }

    @Test
    fun `the HS256 demo token verifies with its secret`() {
        assertEquals(VerificationResult.Valid, verify("valid-hs256.txt", "valid-hs256-secret.txt"))
    }

    @Test
    fun `the RS256 demo token verifies with its public key`() {
        assertEquals(VerificationResult.Valid, verify("expired-rs256.txt", "expired-rs256-public-key.pem"))
    }

    @Test
    fun `the ES256 demo token verifies with its public key`() {
        assertEquals(VerificationResult.Valid, verify("valid-es256.txt", "valid-es256-public-key.pem"))
    }

    @Test
    fun `the PS256 demo token verifies with its public key`() {
        assertEquals(VerificationResult.Valid, verify("valid-ps256.txt", "valid-ps256-public-key.pem"))
    }

    @Test
    fun `the many-claims demo token is reported as unsigned`() {
        val decoded = JwtDecoder.decode(read("many-claims.txt")) as JwtDecodeResult.Success
        assertEquals(VerificationResult.UnsignedToken, JwtVerifier.verify(decoded.token, ""))
    }
}
