// @oagen-ignore-file
package com.workos.android

import com.workos.android.helpers.vaultCrypto
import com.workos.android.support.awaitRequest
import com.workos.android.support.testClientWithStubs
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import java.util.Base64
import javax.crypto.AEADBadTagException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * H18 Vault client-side envelope encryption.
 *
 * The data key is just base64 bytes in the API response, so the whole round trip is
 * testable offline: MockWebServer stubs `createDataKey` and `createDecrypt` with a key
 * this test controls. That makes the envelope layout and the AES-GCM behavior verifiable
 * without a live API, which is what the assertions below actually check — not merely
 * that encrypt-then-decrypt happens to agree with itself.
 */
class VaultCryptoTest {
    // A fixed 32-byte AES-256 key, so failures are reproducible.
    private val keyBytes = ByteArray(32) { it.toByte() }
    private val dataKeyB64: String = Base64.getEncoder().encodeToString(keyBytes)
    private val keyBlobB64: String = Base64.getEncoder().encodeToString("encrypted-key-blob".toByteArray())

    private val dataKeyResponse =
        """
        {"id":"key_1","context":{"tenant":"t1"},"data_key":"$dataKeyB64","encrypted_keys":"$keyBlobB64"}
        """.trimIndent().replace("\n", "")
    private val decryptResponse = """{"id":"key_1","data_key":"$dataKeyB64"}"""

    @Test
    fun `H18 round-trips a plaintext through encrypt and decrypt`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse, decryptResponse))

            val sealed = client.vaultCrypto.encrypt("hello vault", mapOf("tenant" to "t1"))
            val plaintext = client.vaultCrypto.decrypt(sealed)

            assertEquals("hello vault", plaintext)
        }

    @Test
    fun `H18 envelope layout is IV, TAG, LEB128 length, key blob, ciphertext`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse))
            val plaintext = "hello vault"

            val sealed = client.vaultCrypto.encrypt(plaintext, mapOf("tenant" to "t1"))

            val raw = Base64.getDecoder().decode(sealed)
            val keyBlob = "encrypted-key-blob".toByteArray()
            // 12-byte IV, 16-byte tag, then a single LEB128 byte (blob is < 128 bytes).
            // A single-byte LEB128 has its continuation bit (0x80) clear.
            assertEquals(0, raw[12 + 16].toInt() and 0x80, "LEB128 continuation bit should be clear")
            assertEquals(keyBlob.size, raw[28].toInt(), "single-byte LEB128 length")
            val blobStart = 12 + 16 + 1
            assertEquals(
                keyBlob.toList(),
                raw.copyOfRange(blobStart, blobStart + keyBlob.size).toList(),
                "key blob must sit immediately after the length prefix",
            )
            // ciphertext is the remainder, and equals plaintext length for GCM (a stream cipher)
            assertEquals(plaintext.length, raw.size - (blobStart + keyBlob.size))
        }

    @Test
    fun `H18 encrypting twice yields different ciphertext, so the IV is not reused`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse, dataKeyResponse))

            val a = client.vaultCrypto.encrypt("same input", mapOf("tenant" to "t1"))
            val b = client.vaultCrypto.encrypt("same input", mapOf("tenant" to "t1"))

            // Reusing an IV with a GCM key is catastrophic, so this is a security property.
            assertTrue(a != b, "identical ciphertext implies IV reuse")
            val ivA =
                Base64
                    .getDecoder()
                    .decode(a)
                    .copyOfRange(0, 12)
                    .toList()
            val ivB =
                Base64
                    .getDecoder()
                    .decode(b)
                    .copyOfRange(0, 12)
                    .toList()
            assertTrue(ivA != ivB, "IVs must differ per encryption")
        }

    @Test
    fun `H18 a tampered tag fails authentication rather than returning garbage`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse, decryptResponse))
            val sealed = client.vaultCrypto.encrypt("hello vault", mapOf("tenant" to "t1"))

            val raw = Base64.getDecoder().decode(sealed)
            raw[12] = (raw[12].toInt() xor 0xFF).toByte() // flip a bit inside the tag
            val tampered = Base64.getEncoder().encodeToString(raw)

            assertFailsWith<AEADBadTagException> { client.vaultCrypto.decrypt(tampered) }
        }

    @Test
    fun `H18 a tampered ciphertext fails authentication`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse, decryptResponse))
            val sealed = client.vaultCrypto.encrypt("hello vault", mapOf("tenant" to "t1"))

            val raw = Base64.getDecoder().decode(sealed)
            raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0xFF).toByte()

            assertFailsWith<AEADBadTagException> {
                client.vaultCrypto.decrypt(Base64.getEncoder().encodeToString(raw))
            }
        }

    @Test
    fun `H18 associated data is authenticated, so a mismatch fails`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(dataKeyResponse, decryptResponse, dataKeyResponse, decryptResponse))

            val sealed = client.vaultCrypto.encrypt("hello", mapOf("tenant" to "t1"), associatedData = "tenant-1")
            // Same key, same ciphertext, different AAD => must not decrypt.
            assertFailsWith<AEADBadTagException> {
                client.vaultCrypto.decrypt(sealed, associatedData = "tenant-2")
            }
            // And the matching AAD round-trips.
            val again = client.vaultCrypto.encrypt("hello", mapOf("tenant" to "t1"), associatedData = "tenant-1")
            assertEquals("hello", client.vaultCrypto.decrypt(again, associatedData = "tenant-1"))
        }

    @Test
    fun `H18 sends the key context to createDataKey and the blob back to createDecrypt`() =
        runTest {
            val (client, server) = testClientWithStubs(listOf(dataKeyResponse, decryptResponse))

            val sealed = client.vaultCrypto.encrypt("x", mapOf("tenant" to "t1"))
            client.vaultCrypto.decrypt(sealed)

            val encryptRequest = server.awaitRequest()
            assertEquals("/vault/v1/keys/data-key", encryptRequest.path?.substringBefore('?'))
            assertTrue(encryptRequest.body.readUtf8().contains("tenant"))
            val decryptRequest = server.awaitRequest()
            assertEquals("/vault/v1/keys/decrypt", decryptRequest.path?.substringBefore('?'))
            // The blob recovered from the envelope must be what goes back to the API.
            assertTrue(decryptRequest.body.readUtf8().contains(keyBlobB64.replace("=", "")), "key blob not echoed back")
        }

    @Test
    fun `H18 rejects a truncated payload instead of indexing out of bounds`() =
        runTest {
            val (client, _) = testClientWithStubs(listOf(decryptResponse))
            val tooShort = Base64.getEncoder().encodeToString(ByteArray(10))
            assertFailsWith<IllegalArgumentException> { client.vaultCrypto.decrypt(tooShort) }
        }
}
