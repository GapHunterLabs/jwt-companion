package dev.gaphunter.jwtcompanion.ui

import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.components.JBTextField
import dev.gaphunter.jwtcompanion.decode.Claim
import dev.gaphunter.jwtcompanion.decode.ClaimFormatter
import dev.gaphunter.jwtcompanion.decode.JwtDecodeResult
import dev.gaphunter.jwtcompanion.decode.JwtDecoder
import dev.gaphunter.jwtcompanion.decode.JwtToken
import dev.gaphunter.jwtcompanion.decode.TokenTimeStatus
import dev.gaphunter.jwtcompanion.verify.JwtVerifier
import dev.gaphunter.jwtcompanion.verify.VerificationResult
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Font
import java.awt.GridLayout
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.SwingConstants

/**
 * The direct structural fix for the competitor's "fixed two-row table"
 * complaint: header and payload each get their OWN scrollable panel built
 * from a vertical list of claim rows, so a token with 20 claims is exactly
 * as usable as one with 2 -- there is no fixed row count anywhere in this
 * class.
 *
 * Deliberately no platform ToolWindow/project dependency baked into this
 * class beyond what's passed in -- keeps it trivially instantiable outside
 * runIde for the "many claims produces N rows" smoke check described in
 * the plan (a plain Swing component can be constructed and inspected in a
 * headless JVM).
 */
class JwtDecoderPanel : JPanel(BorderLayout()) {

    private val tokenInput = JBTextArea(3, 0).apply {
        lineWrap = true
        wrapStyleWord = false
        emptyText.text = "Paste a JWT here (header.payload.signature)"
    }
    private val statusLabel = JBLabel(" ")
    private val headerClaimsPanel = claimsListPanel()
    private val payloadClaimsPanel = claimsListPanel()
    private val hs256SecretField = JBTextField()
    private val rs256KeyArea = JBTextArea(6, 0).apply {
        emptyText.text = "Paste a PEM public key or certificate here to verify RS256"
    }
    private val verifyResultLabel = JBLabel(" ")

    private var currentToken: JwtToken? = null

    init {
        add(buildTopPanel(), BorderLayout.NORTH)
        add(buildClaimsTabs(), BorderLayout.CENTER)
        add(buildVerifyPanel(), BorderLayout.SOUTH)
    }

    private fun buildTopPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 4, 8)

        val inputScroll = JBScrollPane(tokenInput)
        inputScroll.preferredSize = Dimension(0, 70)
        panel.add(inputScroll, BorderLayout.CENTER)

        val decodeButton = JButton("Decode")
        decodeButton.addActionListener { decode() }
        val buttonRow = JPanel()
        buttonRow.add(decodeButton)
        panel.add(buttonRow, BorderLayout.SOUTH)

        val statusRow = JPanel(BorderLayout())
        statusRow.add(statusLabel, BorderLayout.CENTER)

        val outer = JPanel(BorderLayout())
        outer.add(panel, BorderLayout.CENTER)
        outer.add(statusRow, BorderLayout.SOUTH)
        return outer
    }

    private fun buildClaimsTabs(): JComponent {
        val tabs = JTabbedPane()
        tabs.addTab("Header", JBScrollPane(headerClaimsPanel))
        tabs.addTab("Payload", JBScrollPane(payloadClaimsPanel))
        return tabs
    }

    private fun buildVerifyPanel(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(4, 8, 8, 8),
            BorderFactory.createTitledBorder("Verify Signature"),
        )

        val hsRow = JPanel(GridLayout(1, 2, 6, 0))
        hsRow.add(JBLabel("HS256 secret:"))
        val hsButton = JButton("Verify HS256")
        hsButton.addActionListener { verifyHs256() }
        val hsInputRow = JPanel(BorderLayout(6, 0))
        hsInputRow.add(hs256SecretField, BorderLayout.CENTER)
        hsInputRow.add(hsButton, BorderLayout.EAST)
        panel.add(labeledRow("HS256 shared secret", hsInputRow))

        panel.add(Box.createVerticalStrut(6))

        val rsScroll = JBScrollPane(rs256KeyArea)
        rsScroll.preferredSize = Dimension(0, 90)
        val rsButton = JButton("Verify RS256")
        rsButton.addActionListener { verifyRs256() }
        val rsButtonRow = JPanel()
        rsButtonRow.add(rsButton)
        val rsBlock = JPanel(BorderLayout())
        rsBlock.add(rsScroll, BorderLayout.CENTER)
        rsBlock.add(rsButtonRow, BorderLayout.SOUTH)
        panel.add(labeledRow("RS256 public key / certificate PEM", rsBlock))

        panel.add(Box.createVerticalStrut(4))
        verifyResultLabel.alignmentX = JComponent.LEFT_ALIGNMENT
        panel.add(verifyResultLabel)

        return panel
    }

    private fun labeledRow(label: String, content: JComponent): JComponent {
        val box = Box.createVerticalBox()
        val labelComponent = JBLabel(label)
        labelComponent.alignmentX = JComponent.LEFT_ALIGNMENT
        content.alignmentX = JComponent.LEFT_ALIGNMENT
        box.add(labelComponent)
        box.add(content)
        return box
    }

    private fun claimsListPanel(): JPanel {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        return panel
    }

    fun decode() {
        currentToken = null
        verifyResultLabel.text = " "
        when (val result = JwtDecoder.decode(tokenInput.text)) {
            is JwtDecodeResult.Success -> {
                currentToken = result.token
                statusLabel.text = "Decoded successfully."
                statusLabel.foreground = null
                renderClaims(headerClaimsPanel, result.token.headerClaims, isPayload = false)
                renderClaims(payloadClaimsPanel, result.token.payloadClaims, isPayload = true)
            }
            is JwtDecodeResult.MalformedToken -> {
                statusLabel.text = result.reason
                statusLabel.foreground = JBColor.RED
                clearPanel(headerClaimsPanel)
                clearPanel(payloadClaimsPanel)
            }
        }
    }

    /** Programmatic entry point for the unattended "many claims -> N rows" check -- decodes and returns the claims that would be rendered, without needing the platform running. */
    fun decodeAndGetPayloadClaimRowCount(token: String): Int {
        tokenInput.text = token
        decode()
        return payloadClaimsPanel.componentCount
    }

    private fun clearPanel(panel: JPanel) {
        panel.removeAll()
        panel.revalidate()
        panel.repaint()
    }

    private fun renderClaims(panel: JPanel, claims: List<Claim>, isPayload: Boolean) {
        clearPanel(panel)
        if (claims.isEmpty()) {
            panel.add(JBLabel("No claims."))
        }
        val status = if (isPayload) ClaimFormatter.tokenTimeStatus(claims) else null
        for (claim in claims) {
            panel.add(claimRow(claim, status))
            panel.add(Box.createVerticalStrut(4))
        }
        panel.revalidate()
        panel.repaint()
    }

    private fun claimRow(claim: Claim, tokenStatus: TokenTimeStatus?): JComponent {
        val row = JPanel(BorderLayout(8, 0))
        row.alignmentX = JComponent.LEFT_ALIGNMENT

        val keyLabel = JBLabel(claim.key)
        keyLabel.font = keyLabel.font.deriveFont(Font.BOLD)
        keyLabel.preferredSize = Dimension(140, keyLabel.preferredSize.height)
        row.add(keyLabel, BorderLayout.WEST)

        val displayValue = if (ClaimFormatter.isTimeClaim(claim.key)) {
            "${ClaimFormatter.formatTimeClaim(claim.value)}  (${claim.value})"
        } else {
            claim.value
        }
        val valueLabel = JBLabel(displayValue)
        valueLabel.font = Font(Font.MONOSPACED, Font.PLAIN, valueLabel.font.size)
        if (claim.key == "exp" || claim.key == "nbf") {
            valueLabel.foreground = colorForStatus(tokenStatus)
        }
        row.add(valueLabel, BorderLayout.CENTER)

        return row
    }

    private fun colorForStatus(status: TokenTimeStatus?): Color? = when (status) {
        TokenTimeStatus.EXPIRED, TokenTimeStatus.NOT_YET_VALID -> JBColor.RED
        TokenTimeStatus.EXPIRING_SOON -> JBColor.ORANGE
        else -> null
    }

    private fun verifyHs256() {
        val token = currentToken ?: run {
            verifyResultLabel.text = "Decode a token first."
            verifyResultLabel.foreground = JBColor.RED
            return
        }
        showVerificationResult(JwtVerifier.verifyHs256(token, hs256SecretField.text))
    }

    private fun verifyRs256() {
        val token = currentToken ?: run {
            verifyResultLabel.text = "Decode a token first."
            verifyResultLabel.foreground = JBColor.RED
            return
        }
        showVerificationResult(JwtVerifier.verifyRs256(token, rs256KeyArea.text))
    }

    private fun showVerificationResult(result: VerificationResult) {
        when (result) {
            is VerificationResult.Valid -> {
                verifyResultLabel.text = "Signature is valid."
                verifyResultLabel.foreground = JBColor.GREEN.darker()
            }
            is VerificationResult.InvalidSignature -> {
                verifyResultLabel.text = "Signature does NOT match."
                verifyResultLabel.foreground = JBColor.RED
            }
            is VerificationResult.UnsupportedAlgorithm -> {
                verifyResultLabel.text = "Token uses algorithm '${result.algorithm}', not the one being verified against."
                verifyResultLabel.foreground = JBColor.RED
            }
            is VerificationResult.KeyParseError -> {
                verifyResultLabel.text = result.message
                verifyResultLabel.foreground = JBColor.RED
            }
            is VerificationResult.MalformedToken -> {
                verifyResultLabel.text = "Token is malformed."
                verifyResultLabel.foreground = JBColor.RED
            }
        }
    }
}
