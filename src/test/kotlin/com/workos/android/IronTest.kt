// @oagen-ignore-file
package com.workos.android

import com.workos.android.helpers.Iron
import com.workos.android.helpers.IronException
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Iron Fe26.2 seal/unseal (H06, and the substrate for H04/H05/H07).
 *
 * The load-bearing test here is [`unseals a fixed iron-webcrypto token produced by
 * workos-node`]. Round-trip tests only prove this implementation agrees with itself; a
 * wrong-but-self-consistent port would pass them and then silently fail to read any
 * session cookie written by the Node or Python backends. The fixed token — carried over
 * from workos-kotlin's own test suite, where it came from workos-node — is what actually
 * proves interoperability.
 */
class IronTest {
    private val password = "this-is-at-least-thirty-two-chars!"

    @Test
    fun `unseals a fixed iron-webcrypto token produced by workos-node`() {
        // Cross-SDK vector. If this fails, sealed cookies from Node will not open here.
        val sealed =
            "Fe26.2*1*570ef110e7801942ced24e79800baeb86d4f803120fa48b1c057bfb083ee16d6" +
                "*M5mIO8mKHP8wFo5VxgIC_g*cKhTnmvcPkxH6euF9Bn5TvhrlOvOwQMb92PbnaVMiOs**" +
                "248b6fba3acd1ab0d31c5a2698a057dd0df62e319dce60fae2d4ddd8420e25f6*" +
                "pV7Ipp4YGGBlIdhYCEidU4coZiSLrgyb4qlWXCxDcqk"

        assertEquals("""{"user":"alice"}""", Iron.unseal(sealed, password))
    }

    @Test
    fun `seal then unseal round-trips`() {
        val sealed = Iron.seal("""{"user":"bob"}""", password)
        assertEquals("""{"user":"bob"}""", Iron.unseal(sealed, password))
    }

    @Test
    fun `seal format is Fe26-2 with eight star-separated parts`() {
        val sealed = Iron.seal("payload", password)
        assertTrue(sealed.startsWith("Fe26.2*1*"), sealed)
        assertEquals(8, sealed.split("*").size)
        // No TTL => the expiration field is empty, giving the `**` in the fixture above.
        assertEquals("", sealed.split("*")[5])
    }

    @Test
    fun `two seals of the same data differ, so salts and IV are per-operation`() {
        val a = Iron.seal("same", password)
        val b = Iron.seal("same", password)
        assertTrue(a != b, "identical seals imply a reused salt or IV")
        assertTrue(a.split("*")[2] != b.split("*")[2], "encryption salt must differ")
        assertTrue(a.split("*")[6] != b.split("*")[6], "integrity salt must differ")
    }

    @Test
    fun `unseal rejects a tampered hmac`() {
        val parts = Iron.seal("payload", password).split("*").toMutableList()
        parts[7] = parts[7].dropLast(4) + "AAAA"
        assertFailsWith<IronException> { Iron.unseal(parts.joinToString("*"), password) }
    }

    @Test
    fun `unseal rejects a tampered ciphertext via the hmac, before attempting decryption`() {
        val parts = Iron.seal("payload", password).split("*").toMutableList()
        parts[4] = parts[4].dropLast(4) + "AAAA"
        // The HMAC covers the mac-base string, which includes the ciphertext, so this is
        // caught as a bad HMAC rather than as a padding error.
        val e = assertFailsWith<IronException> { Iron.unseal(parts.joinToString("*"), password) }
        assertTrue(e.message!!.contains("hmac"), e.message!!)
    }

    @Test
    fun `unseal rejects the wrong password`() {
        val sealed = Iron.seal("payload", password)
        assertFailsWith<IronException> { Iron.unseal(sealed, "a-completely-different-32-char-pw!") }
    }

    @Test
    fun `unseal rejects malformed seals`() {
        for (bad in listOf("", "nope", "Fe26.2*1*2*3", "Xx26.2*1*a*b*c**d*e")) {
            assertFailsWith<IronException>("should reject: '$bad'") { Iron.unseal(bad, password) }
        }
    }

    @Test
    fun `seal and unseal reject passwords shorter than 32 characters`() {
        // iron-webcrypto's minimum; a shorter password would weaken key derivation.
        assertFailsWith<IllegalArgumentException> { Iron.seal("x", "too-short") }
        assertFailsWith<IllegalArgumentException> { Iron.unseal(Iron.seal("x", password), "too-short") }
    }

    @Test
    fun `an expired seal is rejected and a live one is accepted`() {
        val issued = 1_700_000_000_000L
        val sealed = Iron.seal("payload", password, ttlMillis = 60_000, nowMillis = issued)

        assertEquals("payload", Iron.unseal(sealed, password, nowMillis = issued + 59_000))
        val e = assertFailsWith<IronException> { Iron.unseal(sealed, password, nowMillis = issued + 60_001) }
        assertTrue(e.message!!.contains("Expired"), e.message!!)
    }

    @Test
    fun `a ttl seal carries the absolute expiry in the expiration field`() {
        val issued = 1_700_000_000_000L
        val sealed = Iron.seal("payload", password, ttlMillis = 60_000, nowMillis = issued)
        assertEquals((issued + 60_000).toString(), sealed.split("*")[5])
    }
}
