// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.WorkOSClient
import com.workos.android.enums.SSOProvider
import com.workos.android.resources.SSO
import com.workos.android.sso
import java.net.URLEncoder

/**
 * H15 — build an SSO authorization URL carrying PKCE parameters.
 *
 * ### Why this is hand-maintained rather than generated
 *
 * `GET /sso/authorize` does accept `code_challenge` and `code_challenge_method`,
 * and enforces `S256` — but both are annotated `@ApiHideProperty()` in the API's
 * `AuthorizationQueryDto`, so they never reach the published OpenAPI document and
 * the generated [SSO.getAuthorizationUrl] therefore has no parameter for them.
 * Every other WorkOS SDK solves this the same way, with a hand-written helper that
 * appends the two hidden parameters (`workos-ios` `SSOHelpers.swift`,
 * `workos-kotlin` `SSOAuthUrls.kt`, `workos-go` `sso_helpers.go`, and the python,
 * ruby, and rust equivalents).
 *
 * This composes over the generated builder rather than reassembling the URL, so
 * every spec-driven parameter and its encoding stays owned by the generator; only
 * the two undocumented parameters are added here.
 *
 * ### There is deliberately no matching code-exchange helper
 *
 * The counterpart — exchanging the returned code with a `code_verifier` and no
 * client secret — is **not** implemented, because `POST /sso/token` cannot do it.
 * `client_secret` is a required field on that endpoint and is validated before any
 * other check, so a secret-less exchange is rejected outright:
 *
 * ```
 * POST /sso/token  {grant_type, client_id, code}          -> 422
 *   {"message":"Validation failed",
 *    "errors":[{"field":"client_secret","code":"client_secret must be a string"}]}
 * ```
 *
 * An Android app cannot hold a client secret, so the exchange leg of SSO PKCE is
 * unavailable until the API accepts `code_verifier` in place of `client_secret`.
 * Sibling SDKs that expose such a method either send the secret anyway — which
 * defeats the purpose and leaves the `code_verifier` unread by the server — or omit
 * it and fail with the 422 above. Neither is worth shipping here.
 *
 * **Use AuthKit instead for a complete PKCE flow on Android:**
 * [getAuthorizationUrlWithPkce] on `userManagement` plus
 * `authenticateWithCode(codeVerifier = …)` is fully supported end to end.
 *
 * @param redirectUri Where WorkOS redirects after authentication. Must be a
 *   configured redirect URI.
 * @param pkce Verifier/challenge generator; inject a fixture in tests.
 * @param state CSRF state echoed back on the redirect. Defaults to a random value.
 */
public fun SSO.getAuthorizationUrlWithPkce(
    redirectUri: String,
    pkce: Pkce = Pkce(),
    state: String = UrlSafeRandom.token(24),
    provider: SSOProvider? = null,
    connection: String? = null,
    organization: String? = null,
    domainHint: String? = null,
    loginHint: String? = null,
    providerScopes: List<String>? = null,
    providerQueryParams: Map<String, String>? = null,
): PkceAuthorizationUrlResult {
    val pair = pkce.generate()
    val base =
        getAuthorizationUrl(
            redirectUri = redirectUri,
            state = state,
            provider = provider,
            connection = connection,
            organization = organization,
            domainHint = domainHint,
            loginHint = loginHint,
            providerScopes = providerScopes,
            providerQueryParams = providerQueryParams,
        )

    // The generated builder always emits `response_type` and `redirect_uri`, so a
    // query string is always present — but the separator is chosen from the actual
    // URL rather than assumed, so this survives a change to that builder.
    val separator = if (base.contains('?')) "&" else "?"
    val challenge = encode(pair.codeChallenge)
    val method = encode(pair.codeChallengeMethod)

    return PkceAuthorizationUrlResult(
        url = "$base${separator}code_challenge=$challenge&code_challenge_method=$method",
        codeVerifier = pair.codeVerifier,
        codeChallenge = pair.codeChallenge,
        state = state,
    )
}

/** Convenience: the same builder reached from the client. */
public fun WorkOSClient.ssoAuthorizationUrlWithPkce(
    redirectUri: String,
    pkce: Pkce = Pkce(),
): PkceAuthorizationUrlResult = this.sso.getAuthorizationUrlWithPkce(redirectUri = redirectUri, pkce = pkce)

/**
 * A base64url code challenge needs no escaping, but encoding it anyway keeps this
 * correct if the challenge derivation ever changes alphabet.
 */
private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
