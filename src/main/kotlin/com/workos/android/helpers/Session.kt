// @oagen-ignore-file
package com.workos.android.helpers

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSourceBuilder
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.workos.android.WorkOSClient
import com.workos.android.WorkOSException
import com.workos.android.internal.workosJson
import com.workos.android.models.AuthenticateResponse
import com.workos.android.models.AuthenticateResponseImpersonator
import com.workos.android.models.User
import com.workos.android.resources.UserManagement
import com.workos.android.userManagement
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

/** Shortest cookie password Iron's key derivation accepts. */
private const val MIN_COOKIE_PASSWORD_CHARS = 32

/** Reason an [SessionCookie.authenticate] call failed. */
public enum class AuthenticateSessionFailureReason {
    /** No sealed session cookie was provided by the caller. */
    NO_SESSION_COOKIE_PROVIDED,

    /** The cookie was malformed, expired, sealed with a different password, or unreadable. */
    INVALID_SESSION_COOKIE,

    /** The access token inside the cookie failed JWKS signature or expiry verification. */
    INVALID_JWT,
}

/** Reason a [SessionCookie.refresh] call failed. */
public enum class RefreshSessionFailureReason {
    /** The cookie was malformed, expired, sealed with a different password, or unreadable. */
    INVALID_SESSION_COOKIE,

    /** The refresh token exchange was rejected by WorkOS as invalid. */
    INVALID_GRANT,

    /** The refresh flow requires the user to complete MFA enrollment first. */
    MFA_ENROLLMENT,

    /** The refresh flow requires an SSO re-authentication step. */
    SSO_REQUIRED,
}

/**
 * The payload carried inside a sealed session cookie.
 *
 * ### Wire format
 *
 * Sealed cookies are a cross-SDK contract: on Android the seal is almost always
 * produced by a *backend* (workos-node, workos-python, …) and merely opened here.
 * So the shape written by [Session.sealAuthResponse] is the one `workos-node`
 * writes — **camelCase at every level**, including inside `user` and
 * `impersonator`:
 *
 * ```json
 * {"accessToken":"…","refreshToken":"…","user":{"emailVerified":true,…}}
 * ```
 *
 * Reading is deliberately more permissive than writing: each key is accepted in
 * either camelCase or snake_case. That makes cookies sealed by `workos-kotlin` —
 * which writes camelCase at the top level but snake_case inside `user`, because
 * its models carry Jackson `@JsonProperty` annotations — readable here too.
 *
 * If the payload ever needs a shape that existing sealed cookies cannot express,
 * add a version field here and gate decoding on it rather than changing a key.
 */
public data class SessionCookieData(
    /** JWT access token used to authenticate API requests. */
    public val accessToken: String,
    /** Refresh token used to obtain a new access token. */
    public val refreshToken: String,
    /** User profile associated with this session. */
    public val user: User? = null,
    /** Method used to authenticate the user (e.g. `"SSO"`, `"Password"`). */
    public val authenticationMethod: String? = null,
    /** The admin impersonating this user, if any. */
    public val impersonator: AuthenticateResponseImpersonator? = null,
)

/** Outcome of [SessionCookie.authenticate]. */
public sealed class AuthenticateSessionResult {
    /** The cookie was valid and its access token verified. */
    public data class Success(
        /** Session identifier from the JWT `sid` claim. */
        public val sessionId: String,
        /** Organization the user authenticated into, if any. */
        public val organizationId: String? = null,
        /** Primary role slug for the user in this organization. */
        public val role: String? = null,
        /** All role slugs assigned to the user. */
        public val roles: List<String>? = null,
        /** Permission slugs granted to the user. */
        public val permissions: List<String>? = null,
        /** Entitlement slugs the user holds. */
        public val entitlements: List<String>? = null,
        /** Feature flag keys enabled for the user. */
        public val featureFlags: List<String>? = null,
        /** User profile from the session cookie. */
        public val user: User? = null,
        /** Method used to authenticate the user. */
        public val authenticationMethod: String? = null,
        /** The admin impersonating this user, if any. */
        public val impersonator: AuthenticateResponseImpersonator? = null,
        /** The verified JWT access token. */
        public val accessToken: String,
    ) : AuthenticateSessionResult()

    /** The cookie could not be authenticated. */
    public data class Failure(
        /** Why authentication failed. */
        public val reason: AuthenticateSessionFailureReason,
    ) : AuthenticateSessionResult()

    /** `true` when this result is a [Success]. */
    public val authenticated: Boolean
        get() = this is Success
}

/** Outcome of [SessionCookie.refresh]. */
public sealed class RefreshSessionResult {
    /** The refresh succeeded; [sealedSession] is the cookie value to persist. */
    public data class Success(
        /** Newly sealed cookie value. Persist this — the old one is now stale. */
        public val sealedSession: String,
        /** Session identifier from the refreshed JWT `sid` claim. */
        public val sessionId: String,
        /** Organization the user is authenticated into, if any. */
        public val organizationId: String? = null,
        /** Primary role slug for the user in this organization. */
        public val role: String? = null,
        /** All role slugs assigned to the user. */
        public val roles: List<String>? = null,
        /** Permission slugs granted to the user. */
        public val permissions: List<String>? = null,
        /** Entitlement slugs the user holds. */
        public val entitlements: List<String>? = null,
        /** Feature flag keys enabled for the user. */
        public val featureFlags: List<String>? = null,
        /** User profile from the session cookie. */
        public val user: User? = null,
        /** Method used to authenticate the user. */
        public val authenticationMethod: String? = null,
        /** The admin impersonating this user, if any. */
        public val impersonator: AuthenticateResponseImpersonator? = null,
    ) : RefreshSessionResult()

    /** The refresh failed. */
    public data class Failure(
        /** Why the refresh failed. */
        public val reason: RefreshSessionFailureReason,
    ) : RefreshSessionResult()

    /** `true` when this result is a [Success]. */
    public val authenticated: Boolean
        get() = this is Success
}

/**
 * Verifies an access token's RS256 signature and expiry.
 *
 * Injectable so tests can verify against a locally generated key pair instead of
 * reaching the network. Production callers get [JwksVerifier], which fetches and
 * caches the environment's JWKS.
 */
internal interface JwtVerifier {
    suspend fun isValid(accessToken: String): Boolean
}

/**
 * Cache of JWT processors, keyed by base URL + client ID.
 *
 * Nimbus's `JWKSourceBuilder` caches the fetched key set and handles rotation, but
 * only for the lifetime of the source — so the source has to outlive the request
 * that created it, or every `authenticate()` would refetch the JWKS.
 */
private object Jwks {
    private val processors = ConcurrentHashMap<String, DefaultJWTProcessor<SecurityContext>>()

    fun processor(
        baseUrl: String,
        clientId: String,
    ): DefaultJWTProcessor<SecurityContext> =
        processors.computeIfAbsent("$baseUrl|$clientId") {
            val url = URL("${baseUrl.trimEnd('/')}/sso/jwks/$clientId")
            val source = JWKSourceBuilder.create<SecurityContext>(url).build()
            DefaultJWTProcessor<SecurityContext>().apply {
                jwsKeySelector = JWSVerificationKeySelector(JWSAlgorithm.RS256, source)
            }
        }
}

/**
 * [JwtVerifier] backed by the live JWKS at `{baseUrl}/sso/jwks/{clientId}`.
 *
 * When [issuers] is non-null the token's `iss` claim must exactly match one of
 * its entries; when null the issuer is not checked.
 */
internal class JwksVerifier(
    private val baseUrl: String,
    private val clientId: String,
    issuers: List<String>? = null,
) : JwtVerifier {
    private val issuers: List<String>? = issuers?.toList()

    /**
     * The JWKS fetch is blocking, so it runs on [Dispatchers.IO] — calling this
     * from the main thread must not stall the UI.
     */
    override suspend fun isValid(accessToken: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                // Rejects a bad signature, an unknown `kid`, and an expired or
                // not-yet-valid token: DefaultJWTProcessor installs a claims
                // verifier that checks `exp`/`nbf`.
                val claims = Jwks.processor(baseUrl, clientId).process(SignedJWT.parse(accessToken), null)
                val accepted = issuers ?: return@withContext true
                val iss = claims.issuer
                iss != null && iss in accepted
            } catch (_: Exception) {
                false
            }
        }
}

/**
 * H04 — a sealed session cookie plus the password that opens it.
 *
 * Construct one per inbound cookie via [Session.loadSealedSession]. [authenticate]
 * validates the seal and the embedded JWT; [refresh] exchanges the embedded
 * refresh token for a new sealed cookie; [getLogoutUrl] derives the logout URL for
 * the current session.
 *
 * [refresh] mutates this instance, so a subsequent [authenticate] sees the new
 * token. Instances are **not** thread-safe — one per request/flow.
 */
public class SessionCookie internal constructor(
    private val userManagement: UserManagement,
    sessionData: String?,
    cookiePassword: String,
    private val verifier: JwtVerifier,
) {
    init {
        // Checked here rather than left to Iron, so a password that is too short
        // surfaces as the configuration error it is instead of being swallowed by
        // authenticate()'s "unreadable cookie" path.
        require(cookiePassword.length >= MIN_COOKIE_PASSWORD_CHARS) {
            "cookiePassword must be at least $MIN_COOKIE_PASSWORD_CHARS characters"
        }
    }

    private var sessionData: String? = sessionData
    private var cookiePassword: String = cookiePassword

    /** Validate the sealed cookie, verify its access token, and decode the JWT claims. */
    public suspend fun authenticate(): AuthenticateSessionResult {
        val data = sessionData
        if (data.isNullOrEmpty()) {
            return AuthenticateSessionResult.Failure(
                AuthenticateSessionFailureReason.NO_SESSION_COOKIE_PROVIDED,
            )
        }

        val session =
            unsealOrNull(data, cookiePassword)
                ?: return AuthenticateSessionResult.Failure(
                    AuthenticateSessionFailureReason.INVALID_SESSION_COOKIE,
                )

        if (session.accessToken.isEmpty()) {
            return AuthenticateSessionResult.Failure(
                AuthenticateSessionFailureReason.INVALID_SESSION_COOKIE,
            )
        }

        if (!verifier.isValid(session.accessToken)) {
            return AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_JWT)
        }

        val claims =
            claimsOrNull(session.accessToken)
                ?: return AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_JWT)

        return AuthenticateSessionResult.Success(
            sessionId = claims.string("sid") ?: "",
            organizationId = claims.string("org_id"),
            role = claims.string("role"),
            roles = claims.stringList("roles"),
            permissions = claims.stringList("permissions"),
            entitlements = claims.stringList("entitlements"),
            featureFlags = claims.stringList("feature_flags"),
            user = session.user,
            authenticationMethod = session.authenticationMethod,
            impersonator = session.impersonator,
            accessToken = session.accessToken,
        )
    }

    /**
     * Exchange the embedded refresh token for a new access token, reseal, and
     * update this instance so a later [authenticate] sees the new token.
     *
     * @param organizationId Organization to refresh into. Defaults to the `org_id`
     *   claim of the current access token.
     * @param newCookiePassword Reseal under a new password, for password rotation.
     */
    public suspend fun refresh(
        organizationId: String? = null,
        newCookiePassword: String? = null,
    ): RefreshSessionResult {
        val data =
            sessionData
                ?: return RefreshSessionResult.Failure(RefreshSessionFailureReason.INVALID_SESSION_COOKIE)

        val session =
            unsealOrNull(data, cookiePassword)
                ?: return RefreshSessionResult.Failure(RefreshSessionFailureReason.INVALID_SESSION_COOKIE)

        if (session.refreshToken.isEmpty()) {
            return RefreshSessionResult.Failure(RefreshSessionFailureReason.INVALID_SESSION_COOKIE)
        }

        // The old token is only a source of a default org hint here, so its
        // signature does not need to be valid — and often is not, since the usual
        // reason to refresh is that it expired.
        val effectiveOrgId = organizationId ?: claimsOrNull(session.accessToken)?.string("org_id")

        val response =
            try {
                userManagement.authenticateWithRefreshToken(
                    refreshToken = session.refreshToken,
                    organizationId = effectiveOrgId,
                )
            } catch (e: WorkOSException) {
                return mapOauthError(e) ?: throw e
            }

        val newPassword = newCookiePassword ?: cookiePassword
        val newSession =
            SessionCookieData(
                accessToken = response.accessToken,
                refreshToken = response.refreshToken,
                user = response.user,
                authenticationMethod = response.authenticationMethod?.rawValue ?: session.authenticationMethod,
                impersonator = session.impersonator,
            )
        val sealed = Iron.seal(encodeSessionCookie(newSession), newPassword)
        sessionData = sealed
        cookiePassword = newPassword

        val claims = claimsOrNull(response.accessToken)
        return RefreshSessionResult.Success(
            sealedSession = sealed,
            sessionId = claims?.string("sid") ?: "",
            organizationId = claims?.string("org_id"),
            role = claims?.string("role"),
            roles = claims?.stringList("roles"),
            permissions = claims?.stringList("permissions"),
            entitlements = claims?.stringList("entitlements"),
            featureFlags = claims?.stringList("feature_flags"),
            user = newSession.user,
            authenticationMethod = newSession.authenticationMethod,
            impersonator = newSession.impersonator,
        )
    }

    /**
     * Build the AuthKit logout URL for the current session.
     *
     * @throws IllegalStateException when the cookie cannot be authenticated, since
     *   there is then no `sid` to log out.
     */
    public suspend fun getLogoutUrl(returnTo: String? = null): String {
        val success =
            when (val auth = authenticate()) {
                is AuthenticateSessionResult.Success -> auth
                is AuthenticateSessionResult.Failure ->
                    throw IllegalStateException(
                        "Failed to extract session ID for logout URL: ${auth.reason}",
                    )
            }
        return userManagement.getLogoutUrl(sessionId = success.sessionId, returnTo = returnTo)
    }

    private fun mapOauthError(e: WorkOSException): RefreshSessionResult.Failure? {
        val reason =
            when (e.code) {
                "invalid_grant" -> RefreshSessionFailureReason.INVALID_GRANT
                "mfa_enrollment" -> RefreshSessionFailureReason.MFA_ENROLLMENT
                "sso_required" -> RefreshSessionFailureReason.SSO_REQUIRED
                else -> return null
            }
        return RefreshSessionResult.Failure(reason)
    }
}

/**
 * H05/H06/H07 — session-cookie helpers, reached as `client.session`.
 *
 * Sealing and unsealing use Iron Fe26.2 ([Iron]), the same scheme every other
 * WorkOS SDK uses, so a cookie sealed by a backend opens here and vice versa.
 */
public class Session internal constructor(
    private val client: WorkOSClient,
) {
    /** Wrap an inbound sealed-cookie value so it can be authenticated or refreshed. */
    public fun loadSealedSession(
        sessionData: String?,
        cookiePassword: String,
    ): SessionCookie = loadSealedSession(sessionData, cookiePassword, issuers = null)

    /**
     * Wrap an inbound sealed-cookie value so it can be authenticated or refreshed.
     *
     * @param issuers Accepted values for the access token's `iss` claim; when null
     *   the issuer is not checked. The match is exact (case-sensitive). The `iss`
     *   value WorkOS mints varies by environment — `https://api.workos.com`,
     *   `https://api.workos.com/user_management/<clientId>`, or a custom auth
     *   domain — so pass the precise value(s) your tokens actually carry.
     *   Enforced by [SessionCookie.authenticate] only, not [SessionCookie.refresh].
     */
    public fun loadSealedSession(
        sessionData: String?,
        cookiePassword: String,
        issuers: List<String>?,
    ): SessionCookie {
        val clientId =
            requireNotNull(client.configuration.clientId) {
                "Missing clientId. Pass it to WorkOSClient — verifying a session's " +
                    "access token requires it to locate the environment's JWKS."
            }
        return SessionCookie(
            userManagement = client.userManagement,
            sessionData = sessionData,
            cookiePassword = cookiePassword,
            verifier = JwksVerifier(client.configuration.baseUrl, clientId, issuers),
        )
    }

    /** Authenticate a sealed cookie in one call. */
    public suspend fun authenticateWithSessionCookie(
        sessionData: String?,
        cookiePassword: String,
    ): AuthenticateSessionResult = authenticateWithSessionCookie(sessionData, cookiePassword, issuers = null)

    /**
     * Authenticate a sealed cookie in one call.
     *
     * @param issuers Accepted values for the access token's `iss` claim; when null
     *   the issuer is not checked. See [loadSealedSession].
     */
    public suspend fun authenticateWithSessionCookie(
        sessionData: String?,
        cookiePassword: String,
        issuers: List<String>?,
    ): AuthenticateSessionResult = loadSealedSession(sessionData, cookiePassword, issuers).authenticate()

    /** Refresh a sealed cookie in one call. */
    public suspend fun refreshSession(
        sessionData: String?,
        cookiePassword: String,
        organizationId: String? = null,
        newCookiePassword: String? = null,
    ): RefreshSessionResult =
        loadSealedSession(sessionData, cookiePassword)
            .refresh(organizationId, newCookiePassword)

    /**
     * H06 — Iron-seal arbitrary JSON.
     *
     * Takes a [JsonObject] rather than a `Map<String, Any?>`: kotlinx.serialization
     * has no serializer for `Any`, and [JsonObject] is the type-safe equivalent.
     * Build one with `buildJsonObject { put("k", "v") }`.
     */
    public fun sealData(
        data: JsonObject,
        cookiePassword: String,
    ): String = Iron.seal(workosJson.encodeToString(JsonObject.serializer(), data), cookiePassword)

    /**
     * H06 — Iron-unseal arbitrary JSON.
     *
     * Returns an empty object for any seal that cannot be opened — wrong password,
     * expired, tampered — matching the Node SDK, which callers rely on to treat a
     * bad cookie as "no session" rather than an error.
     */
    public fun unsealData(
        sealedData: String,
        cookiePassword: String,
    ): JsonObject =
        try {
            workosJson.parseToJsonElement(Iron.unseal(sealedData, cookiePassword)).jsonObject
        } catch (_: IronException) {
            JsonObject(emptyMap())
        } catch (_: SerializationException) {
            JsonObject(emptyMap())
        } catch (_: IllegalArgumentException) {
            // parseToJsonElement returned a non-object; `.jsonObject` rejects it.
            JsonObject(emptyMap())
        }

    /** H07 — seal an [AuthenticateResponse] straight into a session cookie. */
    public fun sealAuthResponse(
        response: AuthenticateResponse,
        cookiePassword: String,
    ): String {
        val payload =
            SessionCookieData(
                accessToken = response.accessToken,
                refreshToken = response.refreshToken,
                user = response.user,
                authenticationMethod = response.authenticationMethod?.rawValue,
                impersonator = response.impersonator,
            )
        return Iron.seal(encodeSessionCookie(payload), cookiePassword)
    }
}

/** Hand-maintained accessor on the client. */
public val WorkOSClient.session: Session
    get() = Session(this)

private fun unsealOrNull(
    sealed: String,
    password: String,
): SessionCookieData? =
    try {
        decodeSessionCookie(Iron.unseal(sealed, password))
    } catch (_: IronException) {
        null
    } catch (_: SerializationException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

private fun claimsOrNull(accessToken: String): JWTClaimsSet? = runCatching { SignedJWT.parse(accessToken).jwtClaimsSet }.getOrNull()

/**
 * Claim accessors that degrade to `null` instead of throwing.
 *
 * Nimbus throws when a claim holds an unexpected JSON type. A single
 * server-introduced type change should narrow one field, not fail the whole
 * authentication.
 */
private fun JWTClaimsSet.string(name: String): String? = runCatching { getStringClaim(name) }.getOrNull()

private fun JWTClaimsSet.stringList(name: String): List<String>? = runCatching { getStringListClaim(name) }.getOrNull()

/**
 * Rename only an object's own keys, never its children's.
 *
 * Depth matters: [User.metadata] holds caller-supplied keys, so recursing would
 * rewrite application data. Both [User] and [AuthenticateResponseImpersonator] are
 * flat apart from `metadata`, and `metadata` itself is unchanged by either
 * transform, so a shallow rename is exactly right here.
 */
private fun JsonObject.renameKeys(transform: (String) -> String): JsonObject = JsonObject(mapKeys { transform(it.key) })

private fun camelToSnake(name: String): String =
    buildString {
        for (c in name) {
            if (c.isUpperCase()) {
                append('_')
                append(c.lowercaseChar())
            } else {
                append(c)
            }
        }
    }

private fun snakeToCamel(name: String): String =
    buildString {
        var upper = false
        for (c in name) {
            when {
                c == '_' -> upper = true
                upper -> {
                    append(c.uppercaseChar())
                    upper = false
                }
                else -> append(c)
            }
        }
    }

private fun <T> encodeCamel(
    serializer: KSerializer<T>,
    value: T,
): JsonObject = workosJson.encodeToJsonElement(serializer, value).jsonObject.renameKeys(::snakeToCamel)

private fun <T> decodeCamelOrSnake(
    serializer: KSerializer<T>,
    obj: JsonObject,
): T = workosJson.decodeFromJsonElement(serializer, obj.renameKeys(::camelToSnake))

/** Serialize a cookie payload in the camelCase form `workos-node` writes. */
internal fun encodeSessionCookie(data: SessionCookieData): String {
    val obj =
        buildJsonObject {
            put("accessToken", data.accessToken)
            put("refreshToken", data.refreshToken)
            data.user?.let { put("user", encodeCamel(User.serializer(), it)) }
            data.authenticationMethod?.let { put("authenticationMethod", it) }
            data.impersonator?.let {
                put("impersonator", encodeCamel(AuthenticateResponseImpersonator.serializer(), it))
            }
        }
    return workosJson.encodeToString(JsonObject.serializer(), obj)
}

/** Parse a cookie payload, accepting camelCase or snake_case keys at any level. */
internal fun decodeSessionCookie(json: String): SessionCookieData {
    val obj = workosJson.parseToJsonElement(json).jsonObject

    fun text(vararg keys: String): String? =
        keys.firstNotNullOfOrNull { key ->
            runCatching { obj[key]?.jsonPrimitive?.contentOrNull }.getOrNull()
        }

    fun nested(key: String): JsonObject? = runCatching { obj[key]?.jsonObject }.getOrNull()

    return SessionCookieData(
        accessToken = text("accessToken", "access_token") ?: "",
        refreshToken = text("refreshToken", "refresh_token") ?: "",
        user = nested("user")?.let { decodeCamelOrSnake(User.serializer(), it) },
        authenticationMethod = text("authenticationMethod", "authentication_method"),
        impersonator =
            nested("impersonator")?.let {
                decodeCamelOrSnake(AuthenticateResponseImpersonator.serializer(), it)
            },
    )
}
