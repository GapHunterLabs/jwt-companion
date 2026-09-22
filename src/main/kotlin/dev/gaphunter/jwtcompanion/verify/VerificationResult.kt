package dev.gaphunter.jwtcompanion.verify

sealed class VerificationResult {
    data object Valid : VerificationResult()
    data object InvalidSignature : VerificationResult()
    data class UnsupportedAlgorithm(val algorithm: String?) : VerificationResult()
    data class KeyParseError(val message: String) : VerificationResult()
    data object MalformedToken : VerificationResult()

    /** `alg: none` (RFC 7519): the token carries no signature, so there is nothing to check it against. */
    data object UnsignedToken : VerificationResult()
}
