package dev.gaphunter.jwtcompanion.decode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MinimalJsonParserTest {

    @Test
    fun `parses a flat object with string and numeric values`() {
        val claims = MinimalJsonParser.parseObject("""{"sub":"1234567890","iat":1700000000}""")
        assertEquals(listOf(Claim("sub", "1234567890"), Claim("iat", "1700000000")), claims)
    }

    @Test
    fun `parses an empty object`() {
        assertEquals(emptyList<Claim>(), MinimalJsonParser.parseObject("{}"))
    }

    @Test
    fun `preserves key order exactly as written in the source`() {
        val claims = MinimalJsonParser.parseObject("""{"z":"1","a":"2","m":"3"}""")
        assertEquals(listOf("z", "a", "m"), claims.map { it.key })
    }

    @Test
    fun `handles escaped characters inside string values`() {
        val claims = MinimalJsonParser.parseObject("""{"note":"line1\nline2\t\"quoted\""}""")
        assertEquals("line1\nline2\t\"quoted\"", claims.first().value)
    }

    @Test
    fun `handles unicode escapes`() {
        val claims = MinimalJsonParser.parseObject("""{"emoji":"é"}""")
        assertEquals("é", claims.first().value)
    }

    @Test
    fun `renders a nested object value as its own compact JSON text, not recursively flattened`() {
        val claims = MinimalJsonParser.parseObject(
            """{"sub":"u1","resource_access":{"app":{"roles":["admin","user"]}}}""",
        )
        assertEquals(2, claims.size)
        assertEquals("""{"app":{"roles":["admin","user"]}}""", claims[1].value)
    }

    @Test
    fun `renders an array value as its own raw text`() {
        val claims = MinimalJsonParser.parseObject("""{"groups":["a","b","c"]}""")
        assertEquals("""["a","b","c"]""", claims.first().value)
    }

    @Test
    fun `handles boolean and null literal values`() {
        val claims = MinimalJsonParser.parseObject("""{"active":true,"deleted":false,"extra":null}""")
        assertEquals("true", claims[0].value)
        assertEquals("false", claims[1].value)
        assertEquals("null", claims[2].value)
    }

    @Test
    fun `throws on input that is not a JSON object`() {
        assertThrows(MinimalJsonParser.JsonParseException::class.java) {
            MinimalJsonParser.parseObject("""["not", "an", "object"]""")
        }
    }

    @Test
    fun `throws on malformed JSON missing a colon`() {
        assertThrows(MinimalJsonParser.JsonParseException::class.java) {
            MinimalJsonParser.parseObject("""{"key" "value"}""")
        }
    }

    @Test
    fun `throws on an unterminated string`() {
        val ex = assertThrows(MinimalJsonParser.JsonParseException::class.java) {
            MinimalJsonParser.parseObject("""{"key":"unterminated""")
        }
        assertTrue(ex.message!!.contains("Unterminated"))
    }
}
