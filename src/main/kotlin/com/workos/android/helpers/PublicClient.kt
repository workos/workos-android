// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.Configuration
import com.workos.android.WorkOSClient
import com.workos.android.internal.JsonBody
import com.workos.android.models.AuthenticateResponse
import com.workos.android.resources.UserManagement
import com.workos.android.userManagement

/**
 * H19 — a client locked to the PKCE / public-client surface.
 *
 * This is the shape an Android app should use. A mobile binary cannot hold a
 * WorkOS API key: anything shipped in the APK is extractable, so the full
 * service API must not be reachable from a distributed app at all. This factory
 * builds a client with an **empty** API key and exposes only the operations that
 * are safe without a client secret — authorization-URL building, PKCE code
 * exchange, refresh-token exchange, and the PKCE helper itself.
 *
 * The empty key is deliberate: if a caller reaches past this facade into the full
 * generated surface, the server rejects the request rather than the mistake going
 * unnoticed in development.
 *
 * ```kotlin
 * val public = PublicClient.create(clientId = "client_123")
 * val start = public.getAuthorizationUrlWithPkce(redirectUri = "app://callback")
 * // ...persist start.codeVerifier, open start.url, handle the redirect...
 * val auth = public.authenticateWithCode(code = code, codeVerifier = verifier)
 * ```
 */
public class PublicClient private constructor(
    internal val client: WorkOSClient,
) {
    /** The WorkOS client ID used for public / PKCE flows. */
    public val clientId: String
        get() =
            client.configuration.clientId
                ?: error("PublicClient requires a clientId")

    /** PKCE helper for generating verifiers and challenges. */
    public val pkce: Pkce get() = Pkce()

    /** Build an AuthKit authorization URL with caller-supplied PKCE parameters. */
    public fun getAuthorizationUrl(
        redirectUri: String,
        codeChallenge: String,
        state: String? = null,
    ): String =
        userManagement.getAuthorizationUrl(
            redirectUri = redirectUri,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            state = state,
        )

    /** Build an AuthKit authorization URL with auto-generated PKCE params and state. */
    public fun getAuthorizationUrlWithPkce(redirectUri: String): PkceAuthorizationUrlResult =
        userManagement.getAuthorizationUrlWithPkce(redirectUri = redirectUri, pkce = pkce)

    /**
     * Exchange an authorization code plus its PKCE verifier for tokens.
     *
     * The body is built here, not by the generated `authenticateWithCode`: that one
     * always sends `client_secret`, and the API rejects an empty one with a 422.
     */
    public suspend fun authenticateWithCode(
        code: String,
        codeVerifier: String,
    ): AuthenticateResponse {
        val payload = JsonBody()
        payload.set("grant_type", "authorization_code")
        payload.set("client_id", clientId)
        payload.set("code", code)
        payload.set("code_verifier", codeVerifier)
        return authenticate(payload)
    }

    /** Exchange a refresh token for new tokens, with no `client_secret`. */
    public suspend fun authenticateWithRefreshToken(
        refreshToken: String,
        organizationId: String? = null,
    ): AuthenticateResponse {
        val payload = JsonBody()
        payload.set("grant_type", "refresh_token")
        payload.set("client_id", clientId)
        payload.set("refresh_token", refreshToken)
        payload.set("organization_id", organizationId)
        return authenticate(payload)
    }

    private suspend fun authenticate(payload: JsonBody): AuthenticateResponse =
        client.transport.request(
            method = "POST",
            path = "user_management/authenticate",
            query = emptyList(),
            body = payload,
            options = null,
        )

    private val userManagement: UserManagement get() = client.userManagement

    public companion object {
        /** Build a public client for [clientId] against [baseUrl]. */
        public fun create(
            clientId: String,
            baseUrl: String = Configuration.DEFAULT_BASE_URL,
        ): PublicClient =
            PublicClient(
                WorkOSClient(
                    Configuration(apiKey = "", baseUrl = baseUrl, clientId = clientId),
                ),
            )
    }
}
