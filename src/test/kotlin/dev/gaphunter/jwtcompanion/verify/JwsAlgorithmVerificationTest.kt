package dev.gaphunter.jwtcompanion.verify

import dev.gaphunter.jwtcompanion.decode.JwtDecodeResult
import dev.gaphunter.jwtcompanion.decode.JwtDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Covers every algorithm the plugin claims to verify, two ways:
 *
 * 1. The published ES256 vector from RFC 7515 Appendix A.3 -- a signature
 *    this code had no part in producing. Signing and verifying with the
 *    same helper would hide a mistake made symmetrically in both
 *    directions, which is exactly the risk with the ECDSA
 *    raw-to-DER conversion.
 * 2. A round trip per algorithm with a freshly generated key, plus the
 *    same token with one payload byte changed, so "valid" means the
 *    signature really is checked and not just parsed.
 */
class JwsAlgorithmVerificationTest {

    private val urlEncoder = Base64.getUrlEncoder().withoutPadding()

    // ---- 1. External vector: RFC 7515 Appendix A.3 (ES256, P-256) -------

    private val rfc7515Header = "eyJhbGciOiJFUzI1NiJ9"
    private val rfc7515Payload =
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    private val rfc7515Signature =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
            "pmWQxfKTUJqPP3-Kg6NU1Q"
    private val rfc7515X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    private val rfc7515Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"

    @Test
    fun `the ES256 vector published in RFC 7515 verifies`() {
        val token = "$rfc7515Header.$rfc7515Payload.$rfc7515Signature"
        val pem = toPem(rfc7515PublicKey())
        assertEquals(VerificationResult.Valid, JwtVerifier.verify(decode(token), pem))
    }

    @Test
    fun `the RFC 7515 vector fails against a different P-256 key`() {
        val token = "$rfc7515Header.$rfc7515Payload.$rfc7515Signature"
        val otherKey = generateKeyPair(JwsAlgorithm.ES256).public
        assertEquals(VerificationResult.InvalidSignature, JwtVerifier.verify(decode(token), toPem(otherKey)))
    }

    private fun rfc7515PublicKey(): PublicKey {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val curve = parameters.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(
            BigInteger(1, Base64.getUrlDecoder().decode(rfc7515X)),
            BigInteger(1, Base64.getUrlDecoder().decode(rfc7515Y)),
        )
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve))
    }

    // ---- 2. Round trip for every supported algorithm --------------------

    @Test
    fun `every supported algorithm verifies its own token`() {
        for (algorithm in JwsAlgorithm.verifiable()) {
            val signed = sign(algorithm)
            assertEquals(
                "${algorithm.alg} should verify",
                VerificationResult.Valid,
                JwtVerifier.verify(decode(signed.token), signed.verificationMaterial),
            )
        }
    }

    @Test
    fun `every supported algorithm rejects a tampered payload`() {
        for (algorithm in JwsAlgorithm.verifiable()) {
            val signed = sign(algorithm)
            // Same signature, payload re-encoded with a different role.
            val tampered = signed.token.split(".").toMutableList()
            tampered[1] = urlEncoder.encodeToString(
                """{"sub":"1","role":"admin"}""".toByteArray(StandardCharsets.UTF_8),
            )
            assertEquals(
                "${algorithm.alg} should reject a tampered payload",
                VerificationResult.InvalidSignature,
                JwtVerifier.verify(decode(tampered.joinToString(".")), signed.verificationMaterial),
            )
        }
    }

    @Test
    fun `every supported algorithm rejects an unrelated key`() {
        for (algorithm in JwsAlgorithm.verifiable()) {
            val signed = sign(algorithm)
            val otherMaterial = if (algorithm.keyMaterial == KeyMaterial.SECRET) {
                "a-completely-different-secret"
            } else {
                toPem(generateKeyPair(algorithm).public)
            }
            assertEquals(
                "${algorithm.alg} should reject an unrelated key",
                VerificationResult.InvalidSignature,
                JwtVerifier.verify(decode(signed.token), otherMaterial),
            )
        }
    }

    // ---- 3. The cases that used to be silent failures --------------------

    @Test
    fun `an unsigned token says so instead of reporting an unsupported algorithm`() {
        val token = urlEncoder.encodeToString("""{"alg":"none"}""".toByteArray()) + "." +
            urlEncoder.encodeToString("""{"sub":"1"}""".toByteArray()) + "."
        assertEquals(VerificationResult.UnsignedToken, JwtVerifier.verify(decode(token), ""))
    }

    @Test
    fun `an RSA key given for an ECDSA token is reported as the wrong key type`() {
        val signed = sign(JwsAlgorithm.ES256)
        val rsaPem = toPem(generateKeyPair(JwsAlgorithm.RS256).public)
        val result = JwtVerifier.verify(decode(signed.token), rsaPem)
        assertTrue("expected a key-type message, got $result", result is VerificationResult.KeyParseError)
        assertTrue((result as VerificationResult.KeyParseError).message.contains("EC key"))
    }

    @Test
    fun `an ECDSA signature of the wrong length is reported with the expected length`() {
        val signed = sign(JwsAlgorithm.ES256)
        val parts = signed.token.split(".").toMutableList()
        val truncated = Base64.getUrlDecoder().decode(parts[2]).copyOfRange(0, 40)
        parts[2] = urlEncoder.encodeToString(truncated)
        val result = JwtVerifier.verify(decode(parts.joinToString(".")), signed.verificationMaterial)
        assertTrue("expected a length message, got $result", result is VerificationResult.KeyParseError)
        assertTrue((result as VerificationResult.KeyParseError).message.contains("64 bytes"))
    }

    @Test
    fun `an algorithm outside the supported set is named in the result`() {
        val token = urlEncoder.encodeToString("""{"alg":"EdDSA"}""".toByteArray()) + "." +
            urlEncoder.encodeToString("""{"sub":"1"}""".toByteArray()) + ".AAAA"
        assertEquals(
            VerificationResult.UnsupportedAlgorithm("EdDSA"),
            JwtVerifier.verify(decode(token), "irrelevant"),
        )
    }

    @Test
    fun `the supported list covers RSA PSS and ECDSA, not just HS256 and RS256`() {
        val supported = JwsAlgorithm.verifiable().map { it.alg }
        assertEquals(
            listOf(
                "HS256", "HS384", "HS512",
                "RS256", "RS384", "RS512",
                "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512",
            ),
            supported,
        )
    }

    // ---- Signing helpers (test-side only) --------------------------------

    private class SignedToken(val token: String, val verificationMaterial: String)

    private val hmacSecret = "round-trip-secret-for-tests"

    private fun sign(algorithm: JwsAlgorithm): SignedToken {
        val header = urlEncoder.encodeToString("""{"alg":"${algorithm.alg}","typ":"JWT"}""".toByteArray())
        val payload = urlEncoder.encodeToString("""{"sub":"1","role":"reader"}""".toByteArray())
        val signingInput = "$header.$payload".toByteArray(StandardCharsets.US_ASCII)

        if (algorithm.keyMaterial == KeyMaterial.SECRET) {
            val mac = Mac.getInstance(algorithm.jcaName)
            mac.init(SecretKeySpec(hmacSecret.toByteArray(StandardCharsets.UTF_8), algorithm.jcaName))
            val signature = urlEncoder.encodeToString(mac.doFinal(signingInput))
            return SignedToken("$header.$payload.$signature", hmacSecret)
        }

        val keyPair = generateKeyPair(algorithm)
        val raw = signAsymmetric(algorithm, keyPair.private, signingInput)
        val signature = urlEncoder.encodeToString(raw)
        return SignedToken("$header.$payload.$signature", toPem(keyPair.public))
    }

    private fun signAsymmetric(algorithm: JwsAlgorithm, key: PrivateKey, signingInput: ByteArray): ByteArray {
        val sig = Signature.getInstance(algorithm.jcaName)
        if (algorithm.pssDigest != null) {
            val mgf1 = when (algorithm.pssDigest) {
                "SHA-384" -> MGF1ParameterSpec.SHA384
                "SHA-512" -> MGF1ParameterSpec.SHA512
                else -> MGF1ParameterSpec.SHA256
            }
            sig.setParameter(
                PSSParameterSpec(algorithm.pssDigest, "MGF1", mgf1, algorithm.pssSaltLength, 1),
            )
        }
        sig.initSign(key)
        sig.update(signingInput)
        val der = sig.sign()
        // A JWS ECDSA signature is raw R || S, so the DER the JDK produces
        // has to be unpacked here -- written out independently of the
        // production code's opposite conversion on purpose.
        return if (algorithm.isEcdsa) derToJose(der, algorithm.ecdsaSignatureLength) else der
    }

    private fun derToJose(der: ByteArray, joseLength: Int): ByteArray {
        var offset = 1
        // Skip the SEQUENCE length (short or long form).
        offset += if (der[offset].toInt() and 0xFF > 0x80) (der[offset].toInt() and 0x7F) + 1 else 1
        require(der[offset].toInt() == 0x02) { "expected an INTEGER for R" }
        val rLength = der[offset + 1].toInt()
        val r = der.copyOfRange(offset + 2, offset + 2 + rLength)
        offset += 2 + rLength
        require(der[offset].toInt() == 0x02) { "expected an INTEGER for S" }
        val sLength = der[offset + 1].toInt()
        val s = der.copyOfRange(offset + 2, offset + 2 + sLength)

        val half = joseLength / 2
        val jose = ByteArray(joseLength)
        copyRightAligned(r, jose, 0, half)
        copyRightAligned(s, jose, half, half)
        return jose
    }

    /** Drops DER's sign byte and left-pads to the curve's fixed width. */
    private fun copyRightAligned(value: ByteArray, target: ByteArray, targetOffset: Int, width: Int) {
        val trimmed = value.dropWhile { it == 0.toByte() }.toByteArray()
        System.arraycopy(trimmed, 0, target, targetOffset + width - trimmed.size, trimmed.size)
    }

    private fun generateKeyPair(algorithm: JwsAlgorithm): KeyPair = when {
        algorithm.isEcdsa -> {
            val curve = when (algorithm) {
                JwsAlgorithm.ES256 -> "secp256r1"
                JwsAlgorithm.ES384 -> "secp384r1"
                else -> "secp521r1"
            }
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
        }
        else -> KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    private fun toPem(key: PublicKey): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(key.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
    }

    private fun decode(token: String) = (JwtDecoder.decode(token) as JwtDecodeResult.Success).token
}
