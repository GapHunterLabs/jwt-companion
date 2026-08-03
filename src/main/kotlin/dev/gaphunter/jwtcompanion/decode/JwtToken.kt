package dev.gaphunter.jwtcompanion.decode

/**
 * A single decoded claim, kept as an ordered list (not a Map) so the UI can
 * render claims in the order they appear in the token instead of an
 * arbitrary hash order -- this is what makes an "N claims" token as
 * scrollable/readable as a 2-claim one.
 */
data class Claim(val key: String, val value: String)

data class JwtToken(
    val headerJson: String,
    val payloadJson: String,
    val headerClaims: List<Claim>,
    val payloadClaims: List<Claim>,
    val signatureBytes: ByteArray,
    val signingInput: ByteArray,
    val algorithm: String?,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JwtToken) return false
        return headerJson == other.headerJson &&
            payloadJson == other.payloadJson &&
            headerClaims == other.headerClaims &&
            payloadClaims == other.payloadClaims &&
            signatureBytes.contentEquals(other.signatureBytes) &&
            signingInput.contentEquals(other.signingInput) &&
            algorithm == other.algorithm
    }

    override fun hashCode(): Int {
        var result = headerJson.hashCode()
        result = 31 * result + payloadJson.hashCode()
        result = 31 * result + headerClaims.hashCode()
        result = 31 * result + payloadClaims.hashCode()
        result = 31 * result + signatureBytes.contentHashCode()
        result = 31 * result + signingInput.contentHashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        return result
    }
}

sealed class JwtDecodeResult {
    data class Success(val token: JwtToken) : JwtDecodeResult()
    data class MalformedToken(val reason: String) : JwtDecodeResult()
}
