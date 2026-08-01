// @oagen-ignore-file
package com.workos.android

import com.workos.android.support.awaitRequest
import com.workos.android.support.headerValue
import com.workos.android.support.testClient
import com.workos.android.support.testClientWithStatus
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Behavior tests for the hand-maintained runtime. The generated per-resource suites
 * cover wire shape; these cover the things the runtime itself is responsible for and
 * that §7 of the runtime contract insists must be proven rather than typed: retries,
 * idempotency, per-request overrides, and typed error translation.
 */
class TransportBehaviorTest {
    private fun client(
        server: MockWebServer,
        maxRetries: Int = 0,
    ) = WorkOSClient(
        Configuration(
            apiKey = "sk_test_123",
            baseUrl = server.url("/").toString().trimEnd('/'),
            maxRetries = maxRetries,
        ),
    )

    /**
     * A COMPLETE Organization payload. The generated model declares seven non-null
     * fields, so a partial fixture fails decoding with MissingFieldException — which
     * is correct strictness (`sdk-runtime-contract.md` §5: missing required fields
     * should fail loudly), not something to work around.
     */
    private val orgJson =
        """
        {"object":"organization","id":"org_1","name":"Acme","domains":[],"metadata":{},
         "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}
        """.trimIndent().replace("\n", "").replace(" ", "")

    @Test
    fun `sends the api key as a bearer token`() =
        runTest {
            val (c, server) = testClient(responding = """{"data":[],"list_metadata":{}}""")

            c.organizations.list()

            assertEquals("Bearer sk_test_123", server.awaitRequest().headerValue("Authorization"))
        }

    @Test
    fun `retries a 500 and then succeeds`() =
        runTest {
            val server = MockWebServer()
            server.start()
            server.enqueue(MockResponse().setResponseCode(500).setBody("""{"message":"boom"}"""))
            server.enqueue(MockResponse().setResponseCode(200).setBody("""{"data":[],"list_metadata":{}}"""))

            client(server, maxRetries = 3).organizations.list()

            assertEquals(2, server.requestCount)
        }

    @Test
    fun `honors Retry-After on a 429`() =
        runTest {
            val server = MockWebServer()
            server.start()
            server.enqueue(
                MockResponse().setResponseCode(429).addHeader("Retry-After", "0").setBody("""{"message":"slow"}"""),
            )
            server.enqueue(MockResponse().setResponseCode(200).setBody("""{"data":[],"list_metadata":{}}"""))

            client(server, maxRetries = 2).organizations.list()

            assertEquals(2, server.requestCount)
        }

    @Test
    fun `stops retrying at maxRetries and throws the typed error`() =
        runTest {
            val server = MockWebServer()
            server.start()
            repeat(3) { server.enqueue(MockResponse().setResponseCode(500).setBody("""{"message":"boom"}""")) }

            val error = runCatching { client(server, maxRetries = 2).organizations.list() }.exceptionOrNull()

            assertTrue(error is ServerException, "expected ServerException, got $error")
            assertEquals(3, server.requestCount) // 1 initial + 2 retries
        }

    @Test
    fun `does not retry a 400`() =
        runTest {
            val server = MockWebServer()
            server.start()
            server.enqueue(MockResponse().setResponseCode(400).setBody("""{"message":"bad"}"""))

            runCatching { client(server, maxRetries = 3).organizations.list() }

            assertEquals(1, server.requestCount)
        }

    @Test
    fun `auto-generates an idempotency key for a retryable POST`() =
        runTest {
            val server = MockWebServer()
            server.start()
            server.enqueue(MockResponse().setResponseCode(500).setBody("""{"message":"boom"}"""))
            server.enqueue(MockResponse().setResponseCode(200).setBody(orgJson))

            runCatching { client(server, maxRetries = 1).organizations.create(name = "Acme") }

            val first = server.awaitRequest().headerValue("Idempotency-Key")
            val second = server.awaitRequest().headerValue("Idempotency-Key")
            assertNotNull(first, "a retryable POST must carry an idempotency key")
            // The SAME key on every attempt, or the retry is not idempotent.
            assertEquals(first, second)
        }

    @Test
    fun `does not add an idempotency key when retries are disabled`() =
        runTest {
            val (c, server) = testClient(responding = orgJson)

            c.organizations.create(name = "Acme")

            assertNull(server.awaitRequest().headerValue("Idempotency-Key"))
        }

    @Test
    fun `caller-supplied idempotency key wins`() =
        runTest {
            val (c, server) = testClient(responding = orgJson)

            c.organizations.create(name = "Acme", requestOptions = RequestOptions(idempotencyKey = "key_abc"))

            assertEquals("key_abc", server.awaitRequest().headerValue("Idempotency-Key"))
        }

    @Test
    fun `request options override the base url`() =
        runTest {
            val other = MockWebServer()
            other.start()
            other.enqueue(MockResponse().setResponseCode(200).setBody("""{"data":[],"list_metadata":{}}"""))
            val (c, primary) = testClient()

            c.organizations.list(
                requestOptions = RequestOptions(baseUrl = other.url("/").toString().trimEnd('/')),
            )

            assertEquals(1, other.requestCount)
            assertEquals(0, primary.requestCount)
        }

    @Test
    fun `translates each status to its typed exception`() =
        runTest {
            val cases =
                listOf(
                    400 to BadRequestException::class,
                    401 to AuthenticationException::class,
                    403 to AuthorizationException::class,
                    404 to NotFoundException::class,
                    409 to ConflictException::class,
                    422 to UnprocessableEntityException::class,
                    429 to RateLimitExceededException::class,
                    503 to ServerException::class,
                )
            for ((status, expected) in cases) {
                val (c, _) = testClientWithStatus(status, """{"message":"nope","code":"some_code"}""")
                val error = runCatching { c.organizations.list() }.exceptionOrNull()
                assertEquals(expected, error!!::class, "status $status mapped to the wrong type")
                assertEquals(status, (error as WorkOSException).statusCode)
                assertEquals("nope", error.message)
                assertEquals("some_code", error.code)
            }
        }

    @Test
    fun `request options override maxRetries, beating the client configuration`() =
        runTest {
            val server = MockWebServer()
            server.start()
            repeat(2) { server.enqueue(MockResponse().setResponseCode(500).setBody("""{"message":"boom"}""")) }
            server.enqueue(MockResponse().setResponseCode(200).setBody("""{"data":[],"list_metadata":{}}"""))

            // The client disables retries entirely; only the per-request override can
            // re-enable them, so a successful call here proves the override is read.
            client(server, maxRetries = 0).organizations.list(requestOptions = RequestOptions(maxRetries = 2))

            assertEquals(3, server.requestCount) // 1 initial + 2 retries
        }

    @Test
    fun `request options override the timeout`() =
        runTest {
            val server = MockWebServer()
            server.start()
            // Answer far later than the per-request timeout allows.
            server.enqueue(
                MockResponse()
                    .setResponseCode(200)
                    .setBody("""{"data":[],"list_metadata":{}}""")
                    .setBodyDelay(5, TimeUnit.SECONDS),
            )

            val error =
                runCatching {
                    client(server, maxRetries = 0).organizations.list(
                        requestOptions = RequestOptions(timeoutSeconds = 1, maxRetries = 0),
                    )
                }.exceptionOrNull()

            // A timeout is a transport failure, so it must surface as the SDK's own
            // NetworkException rather than leaking OkHttp's InterruptedIOException.
            assertTrue(error is NetworkException, "expected NetworkException, got $error")
        }

    /**
     * `requestId` must come from the `x-request-id` response header.
     *
     * The API sends it only as a header — error bodies never carry `request_id`
     * and no schema in the spec declares it — so reading it from the body left
     * this field permanently null on every WorkOSException. It is the field
     * support asks for first, so an always-null slot is worse than useless.
     */
    @Test
    fun `requestId is captured from the x-request-id response header`() =
        runTest {
            val (client, server) =
                testClientWithStatus(
                    404,
                    """{"message":"not found","code":"entity_not_found"}""",
                    headers = mapOf("x-request-id" to "req_01ABCDEF"),
                )
            server.use {
                val error =
                    runCatching { client.organizations.get("org_missing") }.exceptionOrNull()

                val workosError = error as? WorkOSException
                assertNotNull(workosError, "expected a WorkOSException, got $error")
                assertEquals("req_01ABCDEF", workosError.requestId)
                assertEquals(404, workosError.statusCode)
                assertEquals("entity_not_found", workosError.code)
            }
        }

    /** With no header present, the body is still consulted as a forward-compatible fallback. */
    @Test
    fun `requestId falls back to a request_id field in the body`() =
        runTest {
            val (client, server) =
                testClientWithStatus(404, """{"message":"not found","request_id":"req_from_body"}""")
            server.use {
                val error = runCatching { client.organizations.get("org_missing") }.exceptionOrNull()
                assertEquals("req_from_body", (error as? WorkOSException)?.requestId)
            }
        }

    /** Absent from both, it is null rather than a placeholder. */
    @Test
    fun `requestId is null when the API sends none`() =
        runTest {
            val (client, server) = testClientWithStatus(404, """{"message":"not found"}""")
            server.use {
                val error = runCatching { client.organizations.get("org_missing") }.exceptionOrNull()
                assertNull((error as? WorkOSException)?.requestId)
            }
        }
}
