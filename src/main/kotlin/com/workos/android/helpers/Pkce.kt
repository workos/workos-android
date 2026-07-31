// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSClient
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * URL-safe random token generation, shared by the PKCE verifier and the CSRF state
 * in [getAuthorizationUrlWithPkce]. One owner, so a change to the alphabet or
 * padding cannot silently apply to one and not the other.
 */
internal object UrlSafeRandom {
    private val secureRandom = SecureRandom()
    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    /** Base64url-encode [byteCount] cryptographically random bytes. */
    fun token(byteCount: Int): String {
        val raw = ByteArray(byteCount)
        secureRandom.nextBytes(raw)
        return encoder.encodeToString(raw)
    }

    /** Base64url-encode an already-computed digest. */
    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)
}

/** A PKCE (RFC 7636) code verifier and challenge pair. */
public data class PkcePair(
    /** The plain-text code verifier (43-128 characters, RFC 7636 §4.1). */
    public val codeVerifier: String,
    /** Base64url-encoded SHA-256 hash of the code verifier. */
    public val codeChallenge: String,
    /** Challenge derivation method (always `"S256"`). */
    public val codeChallengeMethod: String = "S256",
)

/**
 * PKCE (Proof Key for Code Exchange, RFC 7636) utilities for OAuth 2.0
 * public-client flows — the flow an Android app must use, since it cannot hold a
 * client secret. All operations are stateless.
 *
 * Ported from `workos-kotlin`'s `com.workos.pkce.PKCE` so the two Kotlin SDKs
 * derive challenges identically.
 */
public class Pkce {
    /**
     * Generate a cryptographically random code verifier.
     *
     * @param length verifier length between 43 and 128 characters (RFC 7636 §4.1).
     */
    public fun generateCodeVerifier(length: Int = 43): String {
        require(length in 43..128) {
            "Code verifier length must be between 43 and 128, got $length"
        }
        val numBytes = (length * 3 + 3) / 4
        return UrlSafeRandom.token(numBytes).substring(0, length)
    }

    /** Compute the S256 code challenge (base64url-encoded SHA-256) for a verifier. */
    public fun generateCodeChallenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return UrlSafeRandom.encode(digest)
    }

    /** Generate a complete PKCE pair (verifier + S256 challenge). */
    public fun generate(): PkcePair {
        val verifier = generateCodeVerifier()
        return PkcePair(codeVerifier = verifier, codeChallenge = generateCodeChallenge(verifier))
    }
}

/**
 * Hand-maintained accessor. A same-module extension property, indistinguishable
 * from a generated accessor at the call site; survives regeneration because the
 * emitter never writes into `helpers/`.
 */
public val WorkOSClient.pkce: Pkce
    get() = Pkce()
