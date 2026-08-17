// @oagen-ignore-file
package com.workos.android.internal

import com.workos.android.ApiException
import com.workos.android.AuthenticationException
import com.workos.android.AuthorizationException
import com.workos.android.BadRequestException
import com.workos.android.Configuration
import com.workos.android.ConflictException
import com.workos.android.DecodingException
import com.workos.android.NetworkException
import com.workos.android.NotFoundException
import com.workos.android.RateLimitExceededException
import com.workos.android.RequestOptions
import com.workos.android.ServerException
import com.workos.android.UnprocessableEntityException
import com.workos.android.WorkOSException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.URLEncoder
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.random.Random

/** Status codes worth retrying. */
private val RETRYABLE = setOf(429, 500, 502, 503, 504)

private const val INITIAL_DELAY_MS = 500L
private const val BACKOFF_MULTIPLIER = 2.0
private const val MAX_DELAY_MS = 8_000L
private const val JITTER_FACTOR = 0.5

// Stamped by release-please on every release (see release-please-config.json);
// must stay on one line with the marker comment or it stops being updated.
private const val VERSION = "0.3.0" // x-release-please-version

/**
 * Mirrors the other WorkOS SDKs' `WorkOS <platform>/<version>` shape, which the
 * data platform parses with an end-anchored regex — nothing may follow the version.
 */
private const val USER_AGENT = "WorkOS Android/$VERSION"

/** A fully-read HTTP exchange. Read before any error decision so the body is available. */
private class RawResponse(
    val code: Int,
    val body: String,
    val retryAfterSeconds: Long?,
    /**
     * The `x-request-id` response header. It is the single most useful field when
     * escalating a failure to WorkOS support, and it arrives ONLY as a header —
     * error bodies never contain `request_id`, and no schema in the spec declares
     * it. Reading it from the body left [WorkOSException.requestId] permanently
     * null.
     */
    val requestId: String?,
)

/**
 * OkHttp-backed request execution: URL/query/body assembly, retry with exponential
 * backoff and jitter, `Retry-After`, automatic idempotency keys for retryable POSTs,
 * and translation of every failure into a [WorkOSException].
 *
 * Hand-maintained: the emitter generates resource methods that call into this, never
 * this file.
 */
public class Transport(
    public val configuration: Configuration,
) {
    private val client =
        OkHttpClient
            .Builder()
            .callTimeout(configuration.timeoutSeconds, TimeUnit.SECONDS)
            .build()

    /** Assemble an absolute URL. Also used by the generated URL-builder methods. */
    public fun buildUrl(
        path: String,
        query: List<QueryParam>,
        baseOverride: String? = null,
    ): String {
        val base = (baseOverride ?: configuration.baseUrl).trimEnd('/')
        val qs =
            query.joinToString("&") {
                URLEncoder.encode(it.name, "UTF-8") + "=" + URLEncoder.encode(it.value, "UTF-8")
            }
        return if (qs.isEmpty()) "$base/$path" else "$base/$path?$qs"
    }

    private fun clientFor(options: RequestOptions?): OkHttpClient {
        val timeout = options?.timeoutSeconds ?: return client
        return client.newBuilder().callTimeout(timeout, TimeUnit.SECONDS).build()
    }

    private fun send(
        method: String,
        path: String,
        query: List<QueryParam>,
        body: JsonBody?,
        options: RequestOptions?,
        idempotencyKey: String?,
    ): RawResponse {
        val payload = if (body == null) null else workosJson.encodeToString(JsonElement.serializer(), body.toJsonElement())
        val requestBody =
            when {
                payload != null -> payload.toRequestBody("application/json".toMediaTypeOrNull())
                method == "POST" || method == "PUT" || method == "PATCH" -> "".toRequestBody(null)
                else -> null
            }
        val builder =
            Request
                .Builder()
                .url(buildUrl(path, query, options?.baseUrl))
                .method(method, requestBody)
                .header("Authorization", "Bearer " + configuration.apiKey)
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
        if (idempotencyKey != null) builder.header("Idempotency-Key", idempotencyKey)
        val extra = options?.headers
        if (extra != null) {
            for (entry in extra) builder.header(entry.key, entry.value)
        }
        val response = clientFor(options).newCall(builder.build()).execute()
        val text = response.body?.string() ?: ""
        val code = response.code
        val retryAfter = response.header("Retry-After")?.toLongOrNull()
        // OkHttp's header lookup is case-insensitive, so this covers the
        // `X-Request-Id` / `x-request-id` spellings the API uses interchangeably.
        val requestId = response.header("x-request-id")
        response.close()
        return RawResponse(code, text, retryAfter, requestId)
    }

    /** Backoff for attempt N: initial * multiplier^N, capped, plus jitter. */
    private fun backoffMillis(
        attempt: Int,
        retryAfterSeconds: Long?,
    ): Long {
        if (retryAfterSeconds != null) return retryAfterSeconds * 1_000
        var d = INITIAL_DELAY_MS.toDouble()
        repeat(attempt) { d *= BACKOFF_MULTIPLIER }
        val capped = min(d, MAX_DELAY_MS.toDouble())
        return (capped + capped * JITTER_FACTOR * Random.nextDouble()).toLong()
    }

    /** Execute with retries, returning the raw response body. Throws on non-2xx. */
    public suspend fun execute(
        method: String,
        path: String,
        query: List<QueryParam>,
        body: JsonBody?,
        options: RequestOptions? = null,
    ): String {
        val maxRetries = options?.maxRetries ?: configuration.maxRetries
        // A retried POST must be idempotent, so generate a key once and reuse it
        // across attempts unless the caller supplied one.
        val idempotencyKey =
            options?.idempotencyKey
                ?: if (method == "POST" && maxRetries > 0) UUID.randomUUID().toString() else null

        var attempt = 0
        while (true) {
            val raw =
                try {
                    withContext(Dispatchers.IO) { send(method, path, query, body, options, idempotencyKey) }
                } catch (e: IOException) {
                    if (attempt < maxRetries) {
                        delay(backoffMillis(attempt, null))
                        attempt++
                        continue
                    }
                    throw NetworkException(e.message ?: "connection failed", e)
                }

            if (raw.code in 200..299) return raw.body

            if (raw.code in RETRYABLE && attempt < maxRetries) {
                delay(backoffMillis(attempt, raw.retryAfterSeconds))
                attempt++
                continue
            }
            throw translate(raw)
        }
    }

    /** Execute and decode into [T]. */
    public suspend inline fun <reified T> request(
        method: String,
        path: String,
        query: List<QueryParam>,
        body: JsonBody?,
        options: RequestOptions?,
    ): T {
        val text = execute(method, path, query, body, options)
        return try {
            workosJson.decodeFromString<T>(if (text.isBlank()) "{}" else text)
        } catch (e: IllegalArgumentException) {
            throw DecodingException("could not decode response body", e)
        }
    }

    /** Execute, discarding the body. */
    public suspend fun requestVoid(
        method: String,
        path: String,
        query: List<QueryParam>,
        body: JsonBody?,
        options: RequestOptions?,
    ) {
        execute(method, path, query, body, options)
    }

    private fun translate(raw: RawResponse): WorkOSException {
        val parsed =
            try {
                workosJson.parseToJsonElement(raw.body)
            } catch (e: IllegalArgumentException) {
                null
            }
        val obj = parsed as? JsonObject

        fun str(key: String): String? = (obj?.get(key) as? JsonPrimitive)?.content
        val message = str("message") ?: str("error_description") ?: str("error") ?: "request failed"
        val code = str("code") ?: str("error")
        // Header first, since that is where the API actually sends it; the body
        // read stays as a fallback so this keeps working if it is ever added there.
        val requestId = raw.requestId ?: str("request_id")
        val param = str("param") ?: str("parameter")
        val s = raw.code
        return when (s) {
            400 -> BadRequestException(s, message, code, requestId, param, parsed)
            401 -> AuthenticationException(s, message, code, requestId, param, parsed)
            403 -> AuthorizationException(s, message, code, requestId, param, parsed)
            404 -> NotFoundException(s, message, code, requestId, param, parsed)
            409 -> ConflictException(s, message, code, requestId, param, parsed)
            422 -> UnprocessableEntityException(s, message, code, requestId, param, parsed)
            429 -> RateLimitExceededException(s, message, code, requestId, param, parsed)
            else ->
                if (s >= 500) {
                    ServerException(s, message, code, requestId, param, parsed)
                } else {
                    ApiException(s, message, code, requestId, param, parsed)
                }
        }
    }
}
