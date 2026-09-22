package dev.gaphunter.jwtcompanion.verify

/** What a given `alg` needs from the person verifying it. */
enum class KeyMaterial {
    /** A shared secret (HMAC). */
    SECRET,

    /** A PEM public key or certificate. */
    PUBLIC_KEY,

    /** Nothing to verify against. */
    NONE,
}

/**
 * The JWS algorithms this plugin verifies, all through the JDK's own
 * `javax.crypto`/`java.security` providers -- no bundled crypto library.
 *
 * `alg: none` (RFC 7519) is listed on purpose: an unsigned token is a real
 * thing to run into while debugging, and saying "this token is unsigned,
 * there is nothing to verify" is more useful than "unsupported algorithm".
 */
enum class JwsAlgorithm(
    val alg: String,
    val keyMaterial: KeyMaterial,
    /** JCA name, or null for `none`. */
    val jcaName: String?,
    /** Digest for RSASSA-PSS, null otherwise. */
    val pssDigest: String? = null,
    /** Salt length in bytes for RSASSA-PSS, 0 otherwise. */
    val pssSaltLength: Int = 0,
    /**
     * Expected length of the raw JWS signature for ECDSA (R and S
     * concatenated, fixed width per curve -- RFC 7518 section 3.4), 0 for
     * everything else.
     */
    val ecdsaSignatureLength: Int = 0,
) {
    HS256("HS256", KeyMaterial.SECRET, "HmacSHA256"),
    HS384("HS384", KeyMaterial.SECRET, "HmacSHA384"),
    HS512("HS512", KeyMaterial.SECRET, "HmacSHA512"),

    RS256("RS256", KeyMaterial.PUBLIC_KEY, "SHA256withRSA"),
    RS384("RS384", KeyMaterial.PUBLIC_KEY, "SHA384withRSA"),
    RS512("RS512", KeyMaterial.PUBLIC_KEY, "SHA512withRSA"),

    PS256("PS256", KeyMaterial.PUBLIC_KEY, "RSASSA-PSS", pssDigest = "SHA-256", pssSaltLength = 32),
    PS384("PS384", KeyMaterial.PUBLIC_KEY, "RSASSA-PSS", pssDigest = "SHA-384", pssSaltLength = 48),
    PS512("PS512", KeyMaterial.PUBLIC_KEY, "RSASSA-PSS", pssDigest = "SHA-512", pssSaltLength = 64),

    // P-256, P-384 and P-521: 2 * the curve's coordinate size (P-521's is
    // 66 bytes, not 64 -- 521 bits rounded up).
    ES256("ES256", KeyMaterial.PUBLIC_KEY, "SHA256withECDSA", ecdsaSignatureLength = 64),
    ES384("ES384", KeyMaterial.PUBLIC_KEY, "SHA384withECDSA", ecdsaSignatureLength = 96),
    ES512("ES512", KeyMaterial.PUBLIC_KEY, "SHA512withECDSA", ecdsaSignatureLength = 132),

    NONE("none", KeyMaterial.NONE, null),
    ;

    val isEcdsa: Boolean get() = ecdsaSignatureLength > 0
    val isRsa: Boolean get() = jcaName != null && (jcaName.endsWith("withRSA") || jcaName == "RSASSA-PSS")

    companion object {
        /** Case-sensitive, as RFC 7515 defines these values -- `hs256` is not `HS256`. */
        fun of(alg: String?): JwsAlgorithm? = entries.firstOrNull { it.alg == alg }

        /** For the listing and the tool window's own "supported" line. */
        fun verifiable(): List<JwsAlgorithm> = entries.filter { it.keyMaterial != KeyMaterial.NONE }
    }
}
