// @oagen-ignore-file
package com.workos.android.internal

import java.net.URLEncoder

/**
 * Per-segment path encoding.
 *
 * SECURITY: every generated path-parameter interpolation goes through this. Without
 * per-segment encoding a caller-supplied id containing "../" is normalized away by
 * the HTTP stack (RFC 3986 dot-segment removal) before the request leaves, so the
 * call reaches a different endpoint while still carrying this client's credentials
 * — i.e. forged cross-resource requests under the application's API key.
 */
public object PathEncoding {
    public fun segment(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    public fun segment(value: Any): String = segment(value.toString())
}
