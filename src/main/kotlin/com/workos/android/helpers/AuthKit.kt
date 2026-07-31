// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSClient
import com.workos.android.resources.UserManagement
import com.workos.android.userManagement

/** An AuthKit authorization URL plus the PKCE state the caller must retain. */
public data class PkceAuthorizationUrlResult(
    /** The URL to open in a browser / Custom Tab. */
    public val url: String,
    /**
     * The code verifier. **Must** be stored until the redirect comes back and
     * passed to `authenticateWithCode`, or the exchange cannot be completed.
     */
    public val codeVerifier: String,
    /** The challenge that was sent, derived from [codeVerifier]. */
    public val codeChallenge: String,
    /** The CSRF state parameter that was sent. */
    public val state: String,
)

/** A cryptographically random, URL-safe CSRF state value. */
private fun randomState(): String = UrlSafeRandom.token(24)

/**
 * H10 — build an AuthKit authorization URL that generates its own PKCE parameters
 * and CSRF state, rather than requiring the caller to precompute them.
 *
 * This composes over the GENERATED [UserManagement.getAuthorizationUrl], which
 * already accepts `codeChallenge`, `codeChallengeMethod`, and `state` from the
 * spec — so no wire parameter is invented here. Only the generation and the
 * plumbing of the verifier back to the caller are hand-maintained.
 *
 * The returned [PkceAuthorizationUrlResult.codeVerifier] must survive until the
 * redirect: on Android that means saved instance state or encrypted storage, not
 * an in-memory field on an Activity that can be recreated.
 */
public fun UserManagement.getAuthorizationUrlWithPkce(
    redirectUri: String,
    pkce: Pkce = Pkce(),
    state: String = randomState(),
    provider: com.workos.android.enums.UserManagementAuthenticationProvider? = null,
    connectionId: String? = null,
    organizationId: String? = null,
    loginHint: String? = null,
    domainHint: String? = null,
    screenHint: com.workos.android.enums.UserManagementAuthenticationScreenHint? = null,
): PkceAuthorizationUrlResult {
    val pair = pkce.generate()
    val url =
        getAuthorizationUrl(
            redirectUri = redirectUri,
            codeChallenge = pair.codeChallenge,
            codeChallengeMethod = pair.codeChallengeMethod,
            state = state,
            provider = provider,
            connectionId = connectionId,
            organizationId = organizationId,
            loginHint = loginHint,
            domainHint = domainHint,
            screenHint = screenHint,
        )
    return PkceAuthorizationUrlResult(
        url = url,
        codeVerifier = pair.codeVerifier,
        codeChallenge = pair.codeChallenge,
        state = state,
    )
}

/** Convenience: the same builder reached from the client. */
public fun WorkOSClient.authKitAuthorizationUrlWithPkce(
    redirectUri: String,
    pkce: Pkce = Pkce(),
): PkceAuthorizationUrlResult = this.userManagement.getAuthorizationUrlWithPkce(redirectUri = redirectUri, pkce = pkce)
