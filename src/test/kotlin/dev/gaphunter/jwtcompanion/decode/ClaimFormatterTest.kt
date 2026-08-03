package dev.gaphunter.jwtcompanion.decode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

class ClaimFormatterTest {

    @Test
    fun `formats a valid epoch-seconds claim as a human-readable UTC date`() {
        // 1700000000 seconds since epoch = 2023-11-14 22:13:20 UTC
        val formatted = ClaimFormatter.formatTimeClaim("1700000000")
        assertEquals("2023-11-14 22:13:20 UTC", formatted)
    }

    @Test
    fun `returns the raw text unchanged when it is not a valid epoch number`() {
        assertEquals("not-a-number", ClaimFormatter.formatTimeClaim("not-a-number"))
    }

    @Test
    fun `isTimeClaim recognizes exactly iat, exp, nbf and nothing else`() {
        assertTrue(ClaimFormatter.isTimeClaim("iat"))
        assertTrue(ClaimFormatter.isTimeClaim("exp"))
        assertTrue(ClaimFormatter.isTimeClaim("nbf"))
        assertTrue(!ClaimFormatter.isTimeClaim("sub"))
        assertTrue(!ClaimFormatter.isTimeClaim("name"))
    }

    @Test
    fun `tokenTimeStatus reports EXPIRED when exp is in the past`() {
        val claims = listOf(Claim("exp", "1000"))
        val now = Date(2000L * 1000)
        assertEquals(TokenTimeStatus.EXPIRED, ClaimFormatter.tokenTimeStatus(claims, now))
    }

    @Test
    fun `tokenTimeStatus reports VALID when exp is comfortably in the future`() {
        val claims = listOf(Claim("exp", "9999999999"))
        val now = Date(1_700_000_000L * 1000)
        assertEquals(TokenTimeStatus.VALID, ClaimFormatter.tokenTimeStatus(claims, now))
    }

    @Test
    fun `tokenTimeStatus reports EXPIRING_SOON when exp is within the threshold`() {
        val nowSeconds = 1_700_000_000L
        val claims = listOf(Claim("exp", (nowSeconds + 60).toString())) // 60s from now
        assertEquals(TokenTimeStatus.EXPIRING_SOON, ClaimFormatter.tokenTimeStatus(claims, Date(nowSeconds * 1000)))
    }

    @Test
    fun `tokenTimeStatus reports NOT_YET_VALID when nbf is in the future`() {
        val nowSeconds = 1_700_000_000L
        val claims = listOf(Claim("nbf", (nowSeconds + 3600).toString()), Claim("exp", (nowSeconds + 7200).toString()))
        assertEquals(TokenTimeStatus.NOT_YET_VALID, ClaimFormatter.tokenTimeStatus(claims, Date(nowSeconds * 1000)))
    }

    @Test
    fun `tokenTimeStatus reports UNKNOWN when there is no exp claim`() {
        val claims = listOf(Claim("sub", "1234"))
        assertEquals(TokenTimeStatus.UNKNOWN, ClaimFormatter.tokenTimeStatus(claims))
    }
}
