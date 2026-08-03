package dev.gaphunter.jwtcompanion.verify

import dev.gaphunter.jwtcompanion.decode.JwtToken
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * JDK-only, same philosophy as cert-companion's CertParser: no bundled
 * crypto library, only javax.crypto/java.security. Direct fix for the
 * competitor's "Unsupported algorithm RS256" complaint -- both HS256 and
 * RS256 are supported here, verified against real, independently-generated
 * test vectors (see JwtVerifierTest), not just "looks like it should work."
 */
object JwtVerifier {

    private const val HS256_ALG = "HmacSHA256"
    private const val RS256_ALG = "SHA256withRSA"

    fun verifyHs256(token: JwtToken, secret: String): VerificationResult {
        if (token.algorithm != "HS256") return VerificationResult.UnsupportedAlgorithm(token.algorithm)
        if (secret.isEmpty()) return VerificationResult.KeyParseError("Secret must not be empty.")
        return try {
            val mac = Mac.getInstance(HS256_ALG)
            mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), HS256_ALG))
            val computed = mac.doFinal(token.signingInput)
            // Deliberately NOT computed.contentEquals(token.signatureBytes): a
            // naive byte-array comparison short-circuits on the first
            // mismatching byte, which is a textbook timing side-channel for
            // signature verification. MessageDigest.isEqual is the JDK's own
            // constant-time comparison, built for exactly this case.
            if (java.security.MessageDigest.isEqual(computed, token.signatureBytes)) {
                VerificationResult.Valid
            } else {
                VerificationResult.InvalidSignature
            }
        } catch (e: Exception) {
            VerificationResult.KeyParseError(e.message ?: "Failed to compute HMAC.")
        }
    }

    /**
     * Accepts either a PEM-encoded X.509 certificate (-----BEGIN
     * CERTIFICATE-----) or a PEM-encoded public key
     * (-----BEGIN PUBLIC KEY-----, X.509/SubjectPublicKeyInfo form) --
     * both are common ways an RS256 verification key is shared in practice.
     */
    fun verifyRs256(token: JwtToken, publicKeyOrCertPem: String): VerificationResult {
        if (token.algorithm != "RS256") return VerificationResult.UnsupportedAlgorithm(token.algorithm)
        val publicKey = try {
            parsePublicKey(publicKeyOrCertPem)
        } catch (e: Exception) {
            return VerificationResult.KeyParseError(e.message ?: "Could not parse the provided key/certificate.")
        }
        return try {
            val sig = Signature.getInstance(RS256_ALG)
            sig.initVerify(publicKey)
            sig.update(token.signingInput)
            if (sig.verify(token.signatureBytes)) VerificationResult.Valid else VerificationResult.InvalidSignature
        } catch (e: Exception) {
            VerificationResult.KeyParseError(e.message ?: "Failed to verify RS256 signature.")
        }
    }

    private fun parsePublicKey(pem: String): PublicKey {
        val trimmed = pem.trim()
        if (trimmed.contains("BEGIN CERTIFICATE")) {
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(trimmed.toByteArray(StandardCharsets.UTF_8))) as X509Certificate
            return cert.publicKey
        }
        if (trimmed.contains("BEGIN PUBLIC KEY")) {
            val base64Body = trimmed
                .lineSequence()
                .filterNot { it.startsWith("-----") }
                .joinToString("")
            val keyBytes = Base64.getMimeDecoder().decode(base64Body)
            val spec = X509EncodedKeySpec(keyBytes)
            return KeyFactory.getInstance("RSA").generatePublic(spec)
        }
        throw IllegalArgumentException(
            "Expected a PEM block starting with '-----BEGIN CERTIFICATE-----' or '-----BEGIN PUBLIC KEY-----'.",
        )
    }
}
