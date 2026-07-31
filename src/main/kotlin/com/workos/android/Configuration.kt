// @oagen-ignore-file
package com.workos.android

/**
 * Immutable, instance-scoped client configuration.
 *
 * There is deliberately no global or module-level mutable auth state: every value
 * the runtime needs is read off the client instance
 * (`docs/lang-gen/sdk-runtime-contract.md` §1).
 */
public data class Configuration(
    /** API key. Sent as `Authorization: Bearer <apiKey>`. */
    public val apiKey: String,
    /** API base URL. */
    public val baseUrl: String = DEFAULT_BASE_URL,
    /** Default per-request timeout. */
    public val timeoutSeconds: Long = 60,
    /** Maximum retry attempts for retryable failures. 0 disables retries. */
    public val maxRetries: Int = 3,
    /** AuthKit / SSO client ID, used by the URL builders and PKCE flows. */
    public val clientId: String? = null,
) {
    public companion object {
        public const val DEFAULT_BASE_URL: String = "https://api.workos.com"
    }
}
