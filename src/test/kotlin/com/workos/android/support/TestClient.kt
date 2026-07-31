// @oagen-ignore-file
package com.workos.android.support

import com.workos.android.Configuration
import com.workos.android.WorkOSClient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.TimeUnit

private val testJson = Json { ignoreUnknownKeys = true }

/**
 * Test support for the generated suites. MockWebServer's API is deliberately kept
 * behind these helpers: an OkHttp upgrade (5.x moves MockWebServer to the
 * `mockwebserver3` package) is then a one-file edit rather than a regeneration of
 * every suite.
 *
 * `maxRetries = 0` on every client is required, not incidental: a retryable status
 * (429/5xx) would otherwise consume the single enqueued response on the first
 * attempt and the test would block waiting for one that was never enqueued.
 */
private fun clientFor(server: MockWebServer) =
    WorkOSClient(
        Configuration(
            apiKey = "sk_test_123",
            baseUrl = server.url("/").toString().trimEnd('/'),
            maxRetries = 0,
            clientId = "client_test_123",
        ),
    )

/** A client wired to a server that answers once with 200 and [responding]. */
public fun testClient(responding: String = "{}"): Pair<WorkOSClient, MockWebServer> {
    val server = MockWebServer()
    server.start()
    server.enqueue(MockResponse().setResponseCode(200).setBody(responding))
    return clientFor(server) to server
}

/** A client wired to a server that answers 200 once per entry in [stubs], in order. */
public fun testClientWithStubs(stubs: List<String>): Pair<WorkOSClient, MockWebServer> {
    val server = MockWebServer()
    server.start()
    for (s in stubs) server.enqueue(MockResponse().setResponseCode(200).setBody(s))
    return clientFor(server) to server
}

/** A client wired to a server that answers once with [code] — drives the error-path tests. */
public fun testClientWithStatus(
    code: Int,
    body: String,
    headers: Map<String, String> = emptyMap(),
): Pair<WorkOSClient, MockWebServer> {
    val server = MockWebServer()
    server.start()
    val response = MockResponse().setResponseCode(code).setBody(body)
    for ((k, v) in headers) response.addHeader(k, v)
    server.enqueue(response)
    return clientFor(server) to server
}

/**
 * Take the next request, bounded.
 *
 * `takeRequest()` blocks forever when no request arrives, so a fault where the
 * SDK never issues the call makes the test hang until the CI job times out
 * instead of failing with a usable message. Bounding it turns that into a fast,
 * legible failure.
 */
public fun MockWebServer.awaitRequest(): RecordedRequest =
    takeRequest(5, TimeUnit.SECONDS)
        ?: error("expected the SDK to issue a request, but none arrived within 5s")

/** Request path with the query string stripped. */
public fun RecordedRequest.pathOnly(): String = (path ?: "").substringBefore('?')

/** A single query-parameter value, percent-decoded. */
public fun RecordedRequest.queryParam(name: String): String? = requestUrl?.queryParameter(name)

/** A single request-header value. */
public fun RecordedRequest.headerValue(name: String): String? = getHeader(name)

/** The request body parsed as a JSON object. */
public fun RecordedRequest.bodyJson(): JsonObject = testJson.parseToJsonElement(body.readUtf8()).jsonObject
