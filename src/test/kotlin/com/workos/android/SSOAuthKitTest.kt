// @oagen-ignore-file
package com.workos.android

import com.workos.android.enums.SSOProvider
import com.workos.android.helpers.getAuthorizationUrlWithPkce
import com.workos.android.helpers.ssoAuthorizationUrlWithPkce
import com.workos.android.support.testClient
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SSOAuthKitTest {
    private fun query(url: String) = url.toHttpUrl().let { u -> u.queryParameterNames.associateWith { u.queryParameter(it) } }

    @Test
    fun `sends the PKCE parameters the spec hides`() {
        val (client, server) = testClient()
        server.use {
            val result = client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback")
            val q = query(result.url)

            // These two are absent from the OpenAPI document (@ApiHideProperty) and
            // are the entire reason this helper exists.
            assertEquals(result.codeChallenge, q["code_challenge"])
            assertEquals("S256", q["code_challenge_method"])
        }
    }

    @Test
    fun `preserves every parameter the generated builder emits`() {
        val (client, server) = testClient()
        server.use {
            val result =
                client.sso.getAuthorizationUrlWithPkce(
                    redirectUri = "app://callback",
                    provider = SSOProvider.GoogleOAuth,
                    connection = "conn_123",
                    organization = "org_123",
                    domainHint = "example.com",
                    loginHint = "user@example.com",
                )
            val q = query(result.url)

            assertEquals("code", q["response_type"])
            assertEquals("app://callback", q["redirect_uri"])
            assertEquals("GoogleOAuth", q["provider"])
            assertEquals("conn_123", q["connection"])
            assertEquals("org_123", q["organization"])
            assertEquals("example.com", q["domain_hint"])
            assertEquals("user@example.com", q["login_hint"])
            assertEquals("client_test_123", q["client_id"])
            assertTrue(result.url.startsWith(server.url("/").toString().trimEnd('/') + "/sso/authorize?"), result.url)
        }
    }

    @Test
    fun `the challenge is the S256 hash of the returned verifier`() {
        val (client, server) = testClient()
        server.use {
            val result = client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback")

            // Recompute independently rather than trusting Pkce: this is what the
            // authorization server will do, so a wrong digest or encoding fails here.
            val expected =
                Base64
                    .getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(result.codeVerifier.toByteArray(Charsets.US_ASCII)),
                    )
            assertEquals(expected, result.codeChallenge)
        }
    }

    @Test
    fun `state is echoed into the URL and defaults to a fresh random value`() {
        val (client, server) = testClient()
        server.use {
            val explicit = client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback", state = "st_fixed")
            assertEquals("st_fixed", query(explicit.url)["state"])
            assertEquals("st_fixed", explicit.state)

            val a = client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback")
            val b = client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback")
            assertNotEquals(a.state, b.state, "default state must not be reused across calls")
            assertNotEquals(a.codeVerifier, b.codeVerifier, "each call needs a fresh verifier")
        }
    }

    @Test
    fun `builds the URL without making an HTTP request`() {
        val (client, server) = testClient()
        server.use {
            client.sso.getAuthorizationUrlWithPkce(redirectUri = "app://callback")
            assertEquals(0, server.requestCount, "URL building must not hit the network")
        }
    }

    @Test
    fun `the client-level convenience matches the resource-level builder`() {
        val (client, server) = testClient()
        server.use {
            val q = query(client.ssoAuthorizationUrlWithPkce(redirectUri = "app://callback").url)
            assertEquals("S256", q["code_challenge_method"])
            assertEquals("app://callback", q["redirect_uri"])
            // No secret may ever appear in a URL handed to a browser.
            assertNull(q["client_secret"])
        }
    }
}
