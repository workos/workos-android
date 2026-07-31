// @oagen-ignore-file
package com.workos.android.internal

import kotlinx.serialization.json.Json

/**
 * The single JSON instance the runtime uses.
 *
 * `ignoreUnknownKeys` is essential, not cosmetic: without it a server-added
 * response field throws, so every SDK release would break the moment the API grows
 * a field. Public because [Transport.request] is a public inline function and an
 * inline function cannot reference non-public-API declarations.
 */
public val workosJson: Json =
    Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = false
        coerceInputValues = true
    }
