// @oagen-ignore-file
package com.workos.android.helpers

import com.workos.android.RequestOptions
import com.workos.android.WorkOSClient
import com.workos.android.internal.JsonBody
import com.workos.android.internal.PathEncoding
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Options for creating a magic-link passwordless session. */
public data class CreatePasswordlessSessionOptions(
    /** The email address of the user requesting a magic link. */
    public val email: String,
    /** URL to redirect the user to after clicking the magic link. */
    public val redirectUri: String? = null,
    /** Opaque state parameter returned in the redirect callback. */
    public val state: String? = null,
    /** Connection ID to associate with this passwordless session. */
    public val connection: String? = null,
    /** Number of seconds before the magic link expires. */
    public val expiresIn: Int? = null,
    /** Type of passwordless session (defaults to `"MagicLink"`). */
    public val type: String = "MagicLink",
)

/** Passwordless session returned by [Passwordless.createSession]. */
@Serializable
public data class PasswordlessSession(
    @SerialName("id") public val id: String,
    @SerialName("email") public val email: String,
    /** ISO 8601 timestamp when the magic link expires. */
    @SerialName("expires_at") public val expiresAt: String,
    /** The magic-link URL the user clicks to authenticate. */
    @SerialName("link") public val link: String,
    @SerialName("object") public val `object`: String = "passwordless_session",
)

/** Response returned by [Passwordless.sendSession]. */
@Serializable
public data class SendSessionResponse(
    @SerialName("message") public val message: String? = null,
    @SerialName("success") public val success: Boolean? = null,
)

/**
 * Passwordless (magic-link) sessions.
 *
 * Hand-maintained because `POST /passwordless/sessions` and
 * `POST /passwordless/sessions/{id}/send` are genuinely absent from the OpenAPI
 * spec — confirmed by zero `passwordless` paths in the resolved operation table.
 * If they land in the spec, this module is superseded by generated wrappers.
 *
 * Field names and the `type` default mirror `workos-kotlin`'s
 * `com.workos.passwordless.Passwordless` so both SDKs send the same wire shape.
 */
public class Passwordless internal constructor(
    private val client: WorkOSClient,
) {
    /** Create a magic-link passwordless session. */
    public suspend fun createSession(
        options: CreatePasswordlessSessionOptions,
        requestOptions: RequestOptions? = null,
    ): PasswordlessSession {
        val payload = JsonBody()
        payload.set("type", options.type)
        payload.set("email", options.email)
        payload.set("redirect_uri", options.redirectUri)
        payload.set("state", options.state)
        payload.set("connection", options.connection)
        payload.set("expires_in", options.expiresIn)
        return client.transport.request(
            method = "POST",
            path = "passwordless/sessions",
            query = emptyList(),
            body = payload,
            options = requestOptions,
        )
    }

    /** Send the magic-link email for a previously created session. */
    public suspend fun sendSession(
        sessionId: String,
        requestOptions: RequestOptions? = null,
    ): SendSessionResponse =
        client.transport.request(
            method = "POST",
            path = "passwordless/sessions/${PathEncoding.segment(sessionId)}/send",
            query = emptyList(),
            body = JsonBody(),
            options = requestOptions,
        )
}

/** Hand-maintained accessor on the client. */
public val WorkOSClient.passwordless: Passwordless
    get() = Passwordless(this)
