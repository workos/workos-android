// @oagen-ignore-file
package com.workos.android

import kotlinx.serialization.json.JsonElement
import java.io.IOException

/**
 * Base class for every error the SDK raises. The runtime translates transport and
 * API failures into these rather than leaking OkHttp exceptions
 * (`docs/lang-gen/sdk-runtime-contract.md` §3), and preserves status code, request
 * ID, API error code, the offending parameter, and the raw body.
 *
 * A `Throwable` hierarchy rather than a sealed sum type: it is the Kotlin/JVM
 * convention, and it lets the API add a status code without a breaking change.
 */
public open class WorkOSException(
    public val statusCode: Int,
    override val message: String,
    public val code: String? = null,
    public val requestId: String? = null,
    /** The request parameter the API attributed the error to, when it names one. */
    public val param: String? = null,
    public val raw: JsonElement? = null,
    cause: Throwable? = null,
) : Exception(message, cause)

/** 400 — the request was malformed. */
public class BadRequestException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 401 — authentication failed. */
public class AuthenticationException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 403 — authenticated but not permitted. */
public class AuthorizationException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 404 — the resource was not found. */
public class NotFoundException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 409 — the request conflicts with current state. */
public class ConflictException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 422 — semantically invalid. */
public class UnprocessableEntityException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 429 — rate limited. Retryable; honors `Retry-After`. */
public class RateLimitExceededException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** 5xx — a server error. Retryable. */
public class ServerException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** An unrecognized non-2xx status. */
public class ApiException(
    s: Int,
    m: String,
    c: String? = null,
    r: String? = null,
    p: String? = null,
    raw: JsonElement? = null,
) : WorkOSException(s, m, c, r, p, raw)

/** A connection-level failure (DNS, TCP reset, timeout). */
public class NetworkException(
    m: String,
    cause: IOException,
) : WorkOSException(0, m, cause = cause)

/** The response body could not be decoded into the expected type. */
public class DecodingException(
    m: String,
    cause: Throwable,
) : WorkOSException(0, m, cause = cause)
