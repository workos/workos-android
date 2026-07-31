// @oagen-ignore-file
package com.workos.android

import com.workos.android.internal.Transport

/**
 * The SDK entry point.
 *
 * Resource accessors are generated into `WorkOSClientResources.kt` as extension
 * properties on this class — same module, so they can read [transport] without it
 * becoming public API. Hand-maintained helpers in `helpers/` mount the same way.
 *
 * ```kotlin
 * val client = WorkOSClient(apiKey = "sk_test_...")
 * val org = client.organizations.create(name = "Acme")
 * ```
 */
public class WorkOSClient(
    public val configuration: Configuration,
) {
    public constructor(
        apiKey: String,
        baseUrl: String = Configuration.DEFAULT_BASE_URL,
        clientId: String? = null,
    ) : this(Configuration(apiKey = apiKey, baseUrl = baseUrl, clientId = clientId))

    internal val transport: Transport = Transport(configuration)
}
