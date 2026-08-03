package dev.gaphunter.jwtcompanion.decode

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Same 3-state shape as cert-companion's ExpiryStatus, for the same "at a glance" reason. */
enum class TokenTimeStatus { VALID, EXPIRING_SOON, EXPIRED, NOT_YET_VALID, UNKNOWN }

private val TIME_CLAIM_KEYS = setOf("iat", "exp", "nbf")
private const val EXPIRING_SOON_SECONDS = 5L * 60

object ClaimFormatter {

    private fun dateFormat(): SimpleDateFormat {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt
    }

    fun isTimeClaim(key: String): Boolean = key in TIME_CLAIM_KEYS

    /** Renders a raw numeric-epoch-seconds claim value as a human-readable UTC date, or the raw text if it isn't a valid epoch number. */
    fun formatTimeClaim(rawValue: String): String {
        val epochSeconds = rawValue.toLongOrNull() ?: return rawValue
        return dateFormat().format(Date(epochSeconds * 1000))
    }

    /**
     * Reads exp/nbf directly from the payload claims (not from already
     * human-formatted text) so status computation stays independent of
     * display formatting -- e.g. a locale change to formatTimeClaim() can
     * never silently change what status a token gets classified as.
     */
    fun tokenTimeStatus(payloadClaims: List<Claim>, now: Date = Date()): TokenTimeStatus {
        val nowSeconds = now.time / 1000
        val exp = payloadClaims.firstOrNull { it.key == "exp" }?.value?.toLongOrNull()
        val nbf = payloadClaims.firstOrNull { it.key == "nbf" }?.value?.toLongOrNull()

        if (nbf != null && nowSeconds < nbf) return TokenTimeStatus.NOT_YET_VALID
        if (exp == null) return TokenTimeStatus.UNKNOWN
        if (nowSeconds >= exp) return TokenTimeStatus.EXPIRED
        return if (exp - nowSeconds <= EXPIRING_SOON_SECONDS) TokenTimeStatus.EXPIRING_SOON else TokenTimeStatus.VALID
    }
}
