package dev.gaphunter.jwtcompanion.verify

import dev.gaphunter.jwtcompanion.decode.JwtToken
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Verifies every JWS algorithm in RFC 7518 that the JDK implements --
 * HMAC (HS256/384/512), RSA PKCS#1 v1.5 (RS256/384/512), RSA-PSS
 * (PS256/384/512) and ECDSA (ES256/384/512) -- using only
 * `javax.crypto`/`java.security`, with no bundled crypto library.
 */
object JwtVerifier {

    /** Picks the verification method from the token's own `alg` header. */
    fun verify(token: JwtToken, keyMaterial: String): VerificationResult {
        val algorithm = JwsAlgorithm.of(token.algorithm)
            ?: return VerificationResult.UnsupportedAlgorithm(token.algorithm)
        return when (algorithm.keyMaterial) {
            KeyMaterial.SECRET -> verifyHmac(token, algorithm, keyMaterial)
            KeyMaterial.PUBLIC_KEY -> verifyAsymmetric(token, algorithm, keyMaterial)
            KeyMaterial.NONE -> VerificationResult.UnsignedToken
        }
    }

    /** Kept for callers that already know the token is HS256; [verify] is the general entry point. */
    fun verifyHs256(token: JwtToken, secret: String): VerificationResult {
        if (token.algorithm != "HS256") return VerificationResult.UnsupportedAlgorithm(token.algorithm)
        return verify(token, secret)
    }

    /** Kept for callers that already know the token is RS256; [verify] is the general entry point. */
    fun verifyRs256(token: JwtToken, publicKeyOrCertPem: String): VerificationResult {
        if (token.algorithm != "RS256") return VerificationResult.UnsupportedAlgorithm(token.algorithm)
        return verify(token, publicKeyOrCertPem)
    }

    private fun verifyHmac(token: JwtToken, algorithm: JwsAlgorithm, secret: String): VerificationResult {
        if (secret.isEmpty()) return VerificationResult.KeyParseError("Secret must not be empty.")
        return try {
            val mac = Mac.getInstance(algorithm.jcaName)
            mac.init(SecretKeySpec(secret.toByteArray(StandardCharsets.UTF_8), algorithm.jcaName))
            val computed = mac.doFinal(token.signingInput)
            // Deliberately NOT computed.contentEquals(token.signatureBytes): a
            // naive byte-array comparison short-circuits on the first
            // mismatching byte, which is a textbook timing side-channel for
            // signature verification. MessageDigest.isEqual is the JDK's own
            // constant-time comparison, built for exactly this case.
            if (MessageDigest.isEqual(computed, token.signatureBytes)) {
                VerificationResult.Valid
            } else {
                VerificationResult.InvalidSignature
            }
        } catch (e: Exception) {
            VerificationResult.KeyParseError(e.message ?: "Failed to compute the HMAC.")
        }
    }

    /**
     * Accepts either a PEM-encoded X.509 certificate (BEGIN CERTIFICATE) or
     * a PEM-encoded public key (BEGIN PUBLIC KEY, X.509/SubjectPublicKeyInfo
     * form) -- both are common ways a verification key is shared.
     */
    private fun verifyAsymmetric(token: JwtToken, algorithm: JwsAlgorithm, pem: String): VerificationResult {
        val publicKey = try {
            parsePublicKey(pem, algorithm)
        } catch (e: Exception) {
            return VerificationResult.KeyParseError(e.message ?: "Could not parse the provided key/certificate.")
        }
        val expectedKeyAlgorithm = if (algorithm.isEcdsa) "EC" else "RSA"
        if (!publicKey.algorithm.equals(expectedKeyAlgorithm, ignoreCase = true)) {
            return VerificationResult.KeyParseError(
                "${algorithm.alg} needs an $expectedKeyAlgorithm key, and this one is ${publicKey.algorithm}.",
            )
        }
        val signatureBytes = if (algorithm.isEcdsa) {
            // RFC 7518 section 3.4: a JWS ECDSA signature is R and S
            // concatenated at fixed width, while java.security.Signature
            // speaks the ASN.1 DER form -- so it has to be re-encoded, not
            // passed straight through (skipping this is the usual reason
            // ES256 verification fails for no apparent reason).
            if (token.signatureBytes.size != algorithm.ecdsaSignatureLength) {
                return VerificationResult.KeyParseError(
                    "${algorithm.alg} signatures are ${algorithm.ecdsaSignatureLength} bytes, " +
                        "and this one is ${token.signatureBytes.size}.",
                )
            }
            joseToDer(token.signatureBytes)
        } else {
            token.signatureBytes
        }
        return try {
            val sig = Signature.getInstance(algorithm.jcaName)
            if (algorithm.pssDigest != null) {
                sig.setParameter(
                    PSSParameterSpec(
                        algorithm.pssDigest,
                        "MGF1",
                        mgf1SpecFor(algorithm.pssDigest),
                        algorithm.pssSaltLength,
                        PSSParameterSpec.TRAILER_FIELD_BC,
                    ),
                )
            }
            sig.initVerify(publicKey)
            sig.update(token.signingInput)
            if (sig.verify(signatureBytes)) VerificationResult.Valid else VerificationResult.InvalidSignature
        } catch (e: Exception) {
            VerificationResult.KeyParseError(e.message ?: "Failed to verify the ${algorithm.alg} signature.")
        }
    }

    private fun mgf1SpecFor(digest: String): MGF1ParameterSpec = when (digest) {
        "SHA-384" -> MGF1ParameterSpec.SHA384
        "SHA-512" -> MGF1ParameterSpec.SHA512
        else -> MGF1ParameterSpec.SHA256
    }

    private fun parsePublicKey(pem: String, algorithm: JwsAlgorithm): PublicKey {
        val trimmed = pem.trim()
        if (trimmed.isEmpty()) throw IllegalArgumentException("Paste a PEM public key or certificate first.")
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
            val expected = if (algorithm.isEcdsa) "EC" else "RSA"
            // Try the key type this algorithm needs, then the other one:
            // parsing an RSA key as EC just throws, and "invalid key spec"
            // tells nobody that what they actually pasted was an RSA key
            // for an ES256 token. Whatever parses gets checked against the
            // algorithm by the caller, which can say so in those words.
            return try {
                KeyFactory.getInstance(expected).generatePublic(spec)
            } catch (e: Exception) {
                val fallback = if (expected == "EC") "RSA" else "EC"
                try {
                    KeyFactory.getInstance(fallback).generatePublic(spec)
                } catch (ignored: Exception) {
                    throw e
                }
            }
        }
        throw IllegalArgumentException(
            "Expected a PEM block starting with BEGIN CERTIFICATE or BEGIN PUBLIC KEY.",
        )
    }

    /** `R || S` (fixed width, RFC 7518) to the ASN.1 DER SEQUENCE of two INTEGERs the JDK expects. */
    private fun joseToDer(jose: ByteArray): ByteArray {
        val half = jose.size / 2
        val r = BigInteger(1, jose.copyOfRange(0, half)).toByteArray()
        val s = BigInteger(1, jose.copyOfRange(half, jose.size)).toByteArray()
        val body = ByteArray(2 + r.size + 2 + s.size)
        var i = 0
        body[i++] = 0x02
        body[i++] = r.size.toByte()
        System.arraycopy(r, 0, body, i, r.size)
        i += r.size
        body[i++] = 0x02
        body[i++] = s.size.toByte()
        System.arraycopy(s, 0, body, i, s.size)

        // A P-521 signature pushes the SEQUENCE past 127 bytes, which needs
        // DER's long form for the length byte.
        return if (body.size <= 127) {
            byteArrayOf(0x30, body.size.toByte()) + body
        } else {
            byteArrayOf(0x30, 0x81.toByte(), body.size.toByte()) + body
        }
    }
}
