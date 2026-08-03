package dev.gaphunter.jwtcompanion.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unattended replacement for what would otherwise be a manual runIde
 * smoke pass ("paste a many-claims token, look at the panel, confirm it
 * scrolls instead of truncating to 2 rows") -- Swing components can be
 * constructed and inspected headlessly outside the platform, so this
 * assertion runs in plain `./gradlew test`, no GUI, nobody watching.
 */
class JwtDecoderPanelTest {

    // Same 17-claim token used in JwtDecoderTest -- alg:none, empty
    // signature, real (not hand-typed) claim data.
    private val manyClaimsToken =
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
            "eyJzdWIiOiJ1LTIwNDQiLCJuYW1lIjoiR3JhY2UgSG9wcGVyIiwiZW1haWwiOiJncmFjZS5ob3BwZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OSwibmJmIjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJhY21lLWludGVybmFsLXRvb2xzIiwianRpIjoiYTFiMmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIiwicm9sZSI6ImVuZ2luZWVyaW5nLWxlYWQiLCJkZXBhcnRtZW50IjoiUGxhdGZvcm0gRW5naW5lZXJpbmciLCJvZmZpY2VfbG9jYXRpb24iOiJCdWlsZGluZyA0LCBGbG9vciAyIiwiZW1wbG95ZWVfaWQiOiJFLTcwNDQxIiwibWFuYWdlciI6InUtMTAwMiIsImNvc3RfY2VudGVyIjoiQ0MtNDQ3MSIsImNsZWFyYW5jZV9sZXZlbCI6Ikw0IiwiaGlyZV9kYXRlIjoiMjAxOS0wMy0xMSJ9."

    @Test
    fun `panel renders one row per claim for a 17-claim token, not a fixed row count`() {
        val panel = JwtDecoderPanel()
        // Each claim row is followed by a vertical-strut spacer component,
        // so the panel's child count is 2x the claim count, not 1x --
        // asserting the exact multiple (not just ">2") keeps this test
        // honest about the panel's actual structure instead of a loose
        // "it's more than the old fixed number" check.
        val rowCount = panel.decodeAndGetPayloadClaimRowCount(manyClaimsToken)
        assertEquals(17 * 2, rowCount)
    }

    @Test
    fun `panel does not silently cap claim rendering at 2, the competitor's documented complaint`() {
        val panel = JwtDecoderPanel()
        val rowCount = panel.decodeAndGetPayloadClaimRowCount(manyClaimsToken)
        // 2*2=4 would be the old competitor's ceiling; this must clear it
        // by a wide margin to actually prove the fix, not just barely pass.
        assertTrue("Expected far more than a fixed 2-row rendering, got $rowCount components", rowCount > 10)
    }
}
