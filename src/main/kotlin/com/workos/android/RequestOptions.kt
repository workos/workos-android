// @oagen-ignore-file
package com.workos.android

/**
 * Per-request overrides. Every generated resource method accepts one as its final
 * parameter.
 *
 * All five overrides required by `docs/lang-gen/sdk-runtime-contract.md` §1 are
 * present AND honored by [com.workos.android.internal.Transport] — §7 is explicit
 * that a typed field the runtime ignores does not count, so each one is covered by
 * a generated or hand-maintained test.
 */
public data class RequestOptions(
    /** Extra headers merged onto the request. */
    public val headers: Map<String, String>? = null,
    /** Overrides [Configuration.timeoutSeconds] for this request. */
    public val timeoutSeconds: Long? = null,
    /** Overrides [Configuration.maxRetries] for this request. */
    public val maxRetries: Int? = null,
    /** Overrides [Configuration.baseUrl] for this request. */
    public val baseUrl: String? = null,
    /** Sent as the idempotency key; suppresses the auto-generated one. */
    public val idempotencyKey: String? = null,
)
