// @oagen-ignore-file
package com.workos.android

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.workos.android.helpers.AuthenticateSessionFailureReason
import com.workos.android.helpers.AuthenticateSessionResult
import com.workos.android.helpers.Iron
import com.workos.android.helpers.JwksVerifier
import com.workos.android.helpers.JwtVerifier
import com.workos.android.helpers.RefreshSessionFailureReason
import com.workos.android.helpers.RefreshSessionResult
import com.workos.android.helpers.SessionCookie
import com.workos.android.helpers.SessionCookieData
import com.workos.android.helpers.decodeSessionCookie
import com.workos.android.helpers.encodeSessionCookie
import com.workos.android.helpers.session
import com.workos.android.support.awaitRequest
import com.workos.android.support.bodyJson
import com.workos.android.support.pathOnly
import com.workos.android.support.testClient
import com.workos.android.support.testClientWithStatus
import com.workos.android.userManagement
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.Test
import java.util.Date
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val PASSWORD = "this-is-at-least-thirty-two-chars!"

/** Generated once — RSA keygen is the slowest thing in this suite. */
private val signingKey: RSAKey = RSAKeyGenerator(2048).keyID("test-key-1").generate()

private fun signedJwt(
    key: RSAKey = signingKey,
    expiresInSeconds: Long = 3600,
    claims: Map<String, Any?> = mapOf("sid" to "session_01ABC"),
): String {
    val builder =
        JWTClaimsSet
            .Builder()
            .subject("user_01ABC")
            .expirationTime(Date(System.currentTimeMillis() + expiresInSeconds * 1000))
    for ((k, v) in claims) builder.claim(k, v)
    val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), builder.build())
    jwt.sign(RSASSASigner(key))
    return jwt.serialize()
}

private class FakeVerifier(
    private val valid: Boolean,
) : JwtVerifier {
    var sawToken: String? = null

    override suspend fun isValid(accessToken: String): Boolean {
        sawToken = accessToken
        return valid
    }
}

/** The camelCase user object `workos-node` writes into a sealed cookie. */
private const val NODE_USER_JSON = """
{
  "object": "user",
  "id": "user_01ABC",
  "email": "alice@example.com",
  "emailVerified": true,
  "firstName": "Alice",
  "lastName": "Smith",
  "profilePictureUrl": null,
  "createdAt": "2024-01-01T00:00:00Z",
  "updatedAt": "2024-01-02T00:00:00Z",
  "metadata": {"tenant_id": "t_1", "plan_name": "pro"}
}
"""

/** The same user as `workos-kotlin` writes it — snake_case, because of Jackson's `@JsonProperty`. */
private const val KOTLIN_USER_JSON = """
{
  "object": "user",
  "id": "user_01ABC",
  "email": "alice@example.com",
  "email_verified": true,
  "first_name": "Alice",
  "last_name": "Smith",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-02T00:00:00Z"
}
"""

private fun userResponseJson(id: String = "user_01ABC") =
    """
    {
      "object": "user",
      "id": "$id",
      "email": "alice@example.com",
      "email_verified": true,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-02T00:00:00Z"
    }
    """.trimIndent()

class SessionTest {
    // ---------------------------------------------------------------- wire format

    @Test
    fun `seals in the camelCase shape workos-node reads`() {
        val user = decodeSessionCookie("""{"accessToken":"a","refreshToken":"r","user":$NODE_USER_JSON}""").user
        val json = encodeSessionCookie(SessionCookieData(accessToken = "a", refreshToken = "r", user = user))

        // Top level and nested user are both camelCase — the Node contract.
        assertTrue(json.contains("\"accessToken\""), json)
        assertTrue(json.contains("\"refreshToken\""), json)
        assertTrue(json.contains("\"emailVerified\""), json)
        assertTrue(json.contains("\"profilePictureUrl\"") || !json.contains("profile_picture_url"), json)
        assertFalse(json.contains("email_verified"), json)
        assertFalse(json.contains("first_name"), json)
    }

    @Test
    fun `opens a cookie payload sealed by workos-node`() {
        val payload = """{"accessToken":"tok_a","refreshToken":"tok_r","user":$NODE_USER_JSON}"""
        val data = decodeSessionCookie(payload)

        assertEquals("tok_a", data.accessToken)
        assertEquals("tok_r", data.refreshToken)
        assertEquals("alice@example.com", data.user?.email)
        assertTrue(data.user?.emailVerified == true)
        assertEquals("Alice", data.user?.firstName)
    }

    @Test
    fun `opens a cookie payload sealed by workos-kotlin`() {
        // workos-kotlin's Jackson mapper emits camelCase at the top level but
        // snake_case inside `user`. Both must decode.
        val payload =
            """{"accessToken":"tok_a","refreshToken":"tok_r",""" +
                """"authenticationMethod":"SSO","user":$KOTLIN_USER_JSON}"""
        val data = decodeSessionCookie(payload)

        assertEquals("tok_a", data.accessToken)
        assertEquals("SSO", data.authenticationMethod)
        assertEquals("Alice", data.user?.firstName)
        assertTrue(data.user?.emailVerified == true)
    }

    @Test
    fun `leaves caller-supplied metadata keys untouched`() {
        // The camel/snake rename applies to model fields only. `tenant_id` is
        // application data and must survive a round trip byte-for-byte.
        val user = decodeSessionCookie("""{"accessToken":"a","refreshToken":"r","user":$NODE_USER_JSON}""").user
        assertEquals(mapOf("tenant_id" to "t_1", "plan_name" to "pro"), user?.metadata)

        val round = decodeSessionCookie(encodeSessionCookie(SessionCookieData("a", "r", user)))
        assertEquals(mapOf("tenant_id" to "t_1", "plan_name" to "pro"), round.user?.metadata)
    }

    @Test
    fun `round-trips every cookie field`() {
        val user = decodeSessionCookie("""{"accessToken":"a","refreshToken":"r","user":$NODE_USER_JSON}""").user
        val original =
            SessionCookieData(
                accessToken = "tok_a",
                refreshToken = "tok_r",
                user = user,
                authenticationMethod = "Password",
                impersonator =
                    com.workos.android.models.AuthenticateResponseImpersonator(
                        email = "admin@workos.com",
                        reason = "support ticket 42",
                    ),
            )

        assertEquals(original, decodeSessionCookie(encodeSessionCookie(original)))
    }

    // ---------------------------------------------------------------- authenticate

    @Test
    fun `authenticate reports a missing cookie distinctly from an invalid one`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val result = cookie(client, sessionData = null).authenticate()
                assertEquals(
                    AuthenticateSessionResult.Failure(
                        AuthenticateSessionFailureReason.NO_SESSION_COOKIE_PROVIDED,
                    ),
                    result,
                )
            }
        }

    @Test
    fun `authenticate rejects a malformed seal`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val result = cookie(client, sessionData = "not-an-iron-token").authenticate()
                assertEquals(
                    AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_SESSION_COOKIE),
                    result,
                )
            }
        }

    @Test
    fun `authenticate rejects a seal opened with the wrong password`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData("a", "r")), PASSWORD)
                val result =
                    SessionCookie(
                        client.userManagement,
                        sealed,
                        "a-completely-different-password-32!!",
                        FakeVerifier(true),
                    ).authenticate()
                assertEquals(
                    AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_SESSION_COOKIE),
                    result,
                )
            }
        }

    @Test
    fun `authenticate rejects a cookie whose JWT does not verify`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val verifier = FakeVerifier(valid = false)
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "tok_r")), PASSWORD)
                val result = SessionCookie(client.userManagement, sealed, PASSWORD, verifier).authenticate()

                assertEquals(
                    AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_JWT),
                    result,
                )
                assertNotNull(verifier.sawToken, "the access token must actually reach the verifier")
            }
        }

    @Test
    fun `authenticate decodes every JWT claim it exposes`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val token =
                    signedJwt(
                        claims =
                            mapOf(
                                "sid" to "session_01XYZ",
                                "org_id" to "org_01XYZ",
                                "role" to "admin",
                                "roles" to listOf("admin", "member"),
                                "permissions" to listOf("widgets:read"),
                                "entitlements" to listOf("audit-logs"),
                                "feature_flags" to listOf("new-nav"),
                            ),
                    )
                val user = decodeSessionCookie("""{"accessToken":"a","refreshToken":"r","user":$NODE_USER_JSON}""").user
                val sealed =
                    Iron.seal(
                        encodeSessionCookie(
                            SessionCookieData(token, "tok_r", user, authenticationMethod = "SSO"),
                        ),
                        PASSWORD,
                    )

                val result = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).authenticate()

                val success = assertIs<AuthenticateSessionResult.Success>(result)
                assertTrue(result.authenticated)
                assertEquals("session_01XYZ", success.sessionId)
                assertEquals("org_01XYZ", success.organizationId)
                assertEquals("admin", success.role)
                assertEquals(listOf("admin", "member"), success.roles)
                assertEquals(listOf("widgets:read"), success.permissions)
                assertEquals(listOf("audit-logs"), success.entitlements)
                assertEquals(listOf("new-nav"), success.featureFlags)
                assertEquals("SSO", success.authenticationMethod)
                assertEquals("alice@example.com", success.user?.email)
                assertEquals(token, success.accessToken)
            }
        }

    @Test
    fun `authenticate narrows a claim of the wrong JSON type instead of failing`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                // `roles` arrives as a string rather than an array. The session is
                // still valid; only that one field is unavailable.
                val token = signedJwt(claims = mapOf("sid" to "session_01ABC", "roles" to "admin"))
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(token, "tok_r")), PASSWORD)

                val result = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).authenticate()

                val success = assertIs<AuthenticateSessionResult.Success>(result)
                assertEquals("session_01ABC", success.sessionId)
                assertNull(success.roles)
            }
        }

    @Test
    fun `authenticate rejects an empty access token before calling the verifier`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val verifier = FakeVerifier(true)
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData("", "tok_r")), PASSWORD)
                val result = SessionCookie(client.userManagement, sealed, PASSWORD, verifier).authenticate()

                assertEquals(
                    AuthenticateSessionResult.Failure(AuthenticateSessionFailureReason.INVALID_SESSION_COOKIE),
                    result,
                )
                assertNull(verifier.sawToken)
            }
        }

    // ---------------------------------------------------------------- JWKS verifier

    @Test
    fun `JwksVerifier accepts a token signed by the published key`() =
        runTest {
            jwksServer().use { server ->
                val verifier = JwksVerifier(server.url("/").toString().trimEnd('/'), "client_test_123")
                assertTrue(verifier.isValid(signedJwt()))
            }
        }

    @Test
    fun `JwksVerifier fetches the JWKS from the sso jwks path for the client id`() =
        runTest {
            jwksServer().use { server ->
                JwksVerifier(server.url("/").toString().trimEnd('/'), "client_abc").isValid(signedJwt())
                assertEquals("/sso/jwks/client_abc", server.awaitRequest().pathOnly())
            }
        }

    @Test
    fun `JwksVerifier rejects a tampered payload`() =
        runTest {
            jwksServer().use { server ->
                val verifier = JwksVerifier(server.url("/").toString().trimEnd('/'), "client_test_123")
                val parts = signedJwt().split(".")
                // Swap in a different payload while keeping the original signature.
                val forged = SignedJWT.parse(signedJwt(claims = mapOf("sid" to "attacker")))
                val tampered = "${parts[0]}.${forged.payload.toBase64URL()}.${parts[2]}"
                assertFalse(verifier.isValid(tampered))
            }
        }

    @Test
    fun `JwksVerifier rejects an expired token`() =
        runTest {
            jwksServer().use { server ->
                val verifier = JwksVerifier(server.url("/").toString().trimEnd('/'), "client_test_123")
                assertFalse(verifier.isValid(signedJwt(expiresInSeconds = -60)))
            }
        }

    @Test
    fun `JwksVerifier rejects a token signed by an unpublished key`() =
        runTest {
            jwksServer().use { server ->
                val other = RSAKeyGenerator(2048).keyID("attacker-key").generate()
                val verifier = JwksVerifier(server.url("/").toString().trimEnd('/'), "client_test_123")
                assertFalse(verifier.isValid(signedJwt(key = other)))
            }
        }

    @Test
    fun `JwksVerifier rejects a syntactically invalid token`() =
        runTest {
            jwksServer().use { server ->
                val verifier = JwksVerifier(server.url("/").toString().trimEnd('/'), "client_test_123")
                assertFalse(verifier.isValid("not.a.jwt"))
            }
        }

    // ---------------------------------------------------------------- refresh

    @Test
    fun `refresh exchanges the refresh token and reseals under the same password`() =
        runTest {
            val newToken = signedJwt(claims = mapOf("sid" to "session_02NEW", "org_id" to "org_01XYZ"))
            val (client, server) =
                testClient(
                    """
                    {
                      "user": ${userResponseJson()},
                      "access_token": "$newToken",
                      "refresh_token": "tok_r2",
                      "authentication_method": "SSO"
                    }
                    """.trimIndent(),
                )
            server.use {
                val old = signedJwt(claims = mapOf("sid" to "session_01OLD", "org_id" to "org_01XYZ"))
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(old, "tok_r1")), PASSWORD)
                val handle = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true))

                val result = handle.refresh()
                val success = assertIs<RefreshSessionResult.Success>(result)

                val request = server.awaitRequest()
                assertEquals("POST", request.method)
                assertEquals("/user_management/authenticate", request.pathOnly())
                // Read the body once — RecordedRequest.body is a stream.
                val sent = request.bodyJson()
                assertEquals("tok_r1", sent["refresh_token"]?.jsonPrimitive?.content)
                // org_id is defaulted from the previous access token's claim.
                assertEquals("org_01XYZ", sent["organization_id"]?.jsonPrimitive?.content)

                assertEquals("session_02NEW", success.sessionId)
                assertEquals("org_01XYZ", success.organizationId)
                assertEquals("SSO", success.authenticationMethod)

                // The returned cookie opens under the original password and carries
                // the new tokens.
                val reopened = decodeSessionCookie(Iron.unseal(success.sealedSession, PASSWORD))
                assertEquals(newToken, reopened.accessToken)
                assertEquals("tok_r2", reopened.refreshToken)
            }
        }

    @Test
    fun `refresh updates the handle so a later authenticate sees the new token`() =
        runTest {
            val newToken = signedJwt(claims = mapOf("sid" to "session_02NEW"))
            val (client, server) =
                testClient(
                    """{"user": ${userResponseJson()}, "access_token": "$newToken", "refresh_token": "tok_r2"}""",
                )
            server.use {
                val sealed =
                    Iron.seal(
                        encodeSessionCookie(SessionCookieData(signedJwt(claims = mapOf("sid" to "old")), "tok_r1")),
                        PASSWORD,
                    )
                val handle = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true))

                handle.refresh()

                val after = assertIs<AuthenticateSessionResult.Success>(handle.authenticate())
                assertEquals("session_02NEW", after.sessionId)
            }
        }

    @Test
    fun `refresh reseals under a new password when one is given`() =
        runTest {
            val newToken = signedJwt(claims = mapOf("sid" to "session_02NEW"))
            val (client, server) =
                testClient(
                    """{"user": ${userResponseJson()}, "access_token": "$newToken", "refresh_token": "tok_r2"}""",
                )
            server.use {
                val rotated = "a-rotated-cookie-password-32-chars!!"
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "tok_r1")), PASSWORD)
                val handle = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true))

                val success = assertIs<RefreshSessionResult.Success>(handle.refresh(newCookiePassword = rotated))

                // Opens under the new password only.
                assertEquals(newToken, decodeSessionCookie(Iron.unseal(success.sealedSession, rotated)).accessToken)
                assertFailsWith<com.workos.android.helpers.IronException> {
                    Iron.unseal(success.sealedSession, PASSWORD)
                }
                // ...and the handle now authenticates against the rotated password.
                assertTrue(handle.authenticate().authenticated)
            }
        }

    @Test
    fun `refresh honors an explicit organization id over the token claim`() =
        runTest {
            val (client, server) =
                testClient(
                    """{"user": ${userResponseJson()}, "access_token": "${signedJwt()}", "refresh_token": "r2"}""",
                )
            server.use {
                val old = signedJwt(claims = mapOf("sid" to "s", "org_id" to "org_FROM_CLAIM"))
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(old, "tok_r1")), PASSWORD)

                SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true))
                    .refresh(organizationId = "org_EXPLICIT")

                assertEquals(
                    "org_EXPLICIT",
                    server
                        .takeRequest()
                        .bodyJson()["organization_id"]
                        ?.jsonPrimitive
                        ?.content,
                )
            }
        }

    @Test
    fun `refresh maps known OAuth error codes to typed failure reasons`() =
        runTest {
            val cases =
                mapOf(
                    "invalid_grant" to RefreshSessionFailureReason.INVALID_GRANT,
                    "mfa_enrollment" to RefreshSessionFailureReason.MFA_ENROLLMENT,
                    "sso_required" to RefreshSessionFailureReason.SSO_REQUIRED,
                )
            for ((code, expected) in cases) {
                val (client, server) =
                    testClientWithStatus(400, """{"code":"$code","message":"nope"}""")
                server.use {
                    val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "tok_r1")), PASSWORD)
                    val result =
                        SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).refresh()
                    assertEquals(RefreshSessionResult.Failure(expected), result, "code=$code")
                    assertFalse(result.authenticated)
                }
            }
        }

    @Test
    fun `refresh rethrows an API error it has no reason for`() =
        runTest {
            val (client, server) = testClientWithStatus(500, """{"code":"internal_error","message":"boom"}""")
            server.use {
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "tok_r1")), PASSWORD)
                assertFailsWith<WorkOSException> {
                    SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).refresh()
                }
            }
        }

    @Test
    fun `refresh rejects a cookie with no refresh token without calling the API`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "")), PASSWORD)
                val result = SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).refresh()

                assertEquals(
                    RefreshSessionResult.Failure(RefreshSessionFailureReason.INVALID_SESSION_COOKIE),
                    result,
                )
                assertEquals(0, server.requestCount)
            }
        }

    // ---------------------------------------------------------------- logout URL

    @Test
    fun `getLogoutUrl carries the session id from the verified token`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val token = signedJwt(claims = mapOf("sid" to "session_01LOGOUT"))
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(token, "tok_r")), PASSWORD)

                val url =
                    SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true))
                        .getLogoutUrl(returnTo = "https://app.example.com/bye")

                assertTrue(url.contains("/user_management/sessions/logout"), url)
                assertTrue(url.contains("session_id=session_01LOGOUT"), url)
                assertTrue(url.contains("return_to=https%3A%2F%2Fapp.example.com%2Fbye"), url)
            }
        }

    @Test
    fun `getLogoutUrl fails loudly when the session cannot be authenticated`() =
        runTest {
            val (client, server) = testClient()
            server.use {
                val sealed = Iron.seal(encodeSessionCookie(SessionCookieData(signedJwt(), "tok_r")), PASSWORD)
                val error =
                    assertFailsWith<IllegalStateException> {
                        SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(false)).getLogoutUrl()
                    }
                assertTrue(error.message?.contains("INVALID_JWT") == true, error.message)
            }
        }

    // ---------------------------------------------------------------- raw seal / unseal

    @Test
    fun `sealData and unsealData round-trip arbitrary JSON`() {
        val (client, server) = testClient()
        server.use {
            val data =
                buildJsonObject {
                    put("user", "alice")
                    put("count", 3)
                }
            val sealed = client.session.sealData(data, PASSWORD)
            assertEquals(data, client.session.unsealData(sealed, PASSWORD))
        }
    }

    @Test
    fun `unsealData yields an empty object rather than throwing on a bad seal`() {
        val (client, server) = testClient()
        server.use {
            val sealed = client.session.sealData(buildJsonObject { put("user", "alice") }, PASSWORD)

            assertTrue(client.session.unsealData(sealed, "another-password-of-32-characters!!").isEmpty())
            assertTrue(client.session.unsealData("garbage", PASSWORD).isEmpty())
        }
    }

    @Test
    fun `unsealData yields an empty object for a seal whose TTL has passed`() {
        val (client, server) = testClient()
        server.use {
            val expired =
                Iron.seal("""{"user":"alice"}""", PASSWORD, ttlMillis = 1, nowMillis = 1_000)
            assertTrue(client.session.unsealData(expired, PASSWORD).isEmpty())
        }
    }

    // ---------------------------------------------------------------- H07 + accessor

    @Test
    fun `sealAuthResponse produces a cookie that authenticates`() =
        runTest {
            val token = signedJwt(claims = mapOf("sid" to "session_01SEALED", "org_id" to "org_01ABC"))
            val (client, server) =
                testClient(
                    """
                    {
                      "user": ${userResponseJson()},
                      "access_token": "$token",
                      "refresh_token": "tok_r",
                      "authentication_method": "Password",
                      "impersonator": {"email": "admin@workos.com", "reason": "support"}
                    }
                    """.trimIndent(),
                )
            server.use {
                val response = client.userManagement.authenticateWithPassword(email = "a@b.com", password = "pw")
                val sealed = client.session.sealAuthResponse(response, PASSWORD)

                val result =
                    SessionCookie(client.userManagement, sealed, PASSWORD, FakeVerifier(true)).authenticate()
                val success = assertIs<AuthenticateSessionResult.Success>(result)

                assertEquals("session_01SEALED", success.sessionId)
                assertEquals("org_01ABC", success.organizationId)
                assertEquals("Password", success.authenticationMethod)
                assertEquals("admin@workos.com", success.impersonator?.email)
                assertEquals("alice@example.com", success.user?.email)
            }
        }

    @Test
    fun `loadSealedSession requires a client id for JWKS verification`() {
        val server = MockWebServer()
        server.start()
        server.use {
            val noClientId =
                WorkOSClient(Configuration(apiKey = "sk_test_123", baseUrl = server.url("/").toString().trimEnd('/')))
            val error =
                assertFailsWith<IllegalArgumentException> {
                    noClientId.session.loadSealedSession("whatever", PASSWORD)
                }
            assertTrue(error.message?.contains("clientId") == true, error.message)
        }
    }

    @Test
    fun `a cookie password shorter than Iron accepts is a configuration error`() {
        val (client, server) = testClient()
        server.use {
            assertFailsWith<IllegalArgumentException> {
                SessionCookie(client.userManagement, "whatever", "too-short", FakeVerifier(true))
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun cookie(
        client: WorkOSClient,
        sessionData: String?,
        password: String = PASSWORD,
        valid: Boolean = true,
    ) = SessionCookie(client.userManagement, sessionData, password, FakeVerifier(valid))

    private fun jwksServer(): MockWebServer {
        val body = """{"keys":[${signingKey.toPublicJWK().toJSONString()}]}"""
        val server = MockWebServer()
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    MockResponse()
                        .setResponseCode(200)
                        .addHeader("Content-Type", "application/json")
                        .setBody(body)
            }
        server.start()
        return server
    }
}
