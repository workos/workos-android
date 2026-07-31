// @oagen-ignore-file
package com.workos.android

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Cursor pagination metadata. */
@Serializable
public data class ListMetadata(
    @SerialName("before") public val before: String? = null,
    @SerialName("after") public val after: String? = null,
)

/**
 * A single page of results. Generated list methods return this rather than a raw
 * list, so the cursors stay reachable (`sdk-runtime-contract.md` §4). Each
 * cursor-paginated operation also gets a generated `…AutoPaging` companion
 * returning a `Flow` that walks every page.
 */
@Serializable
public data class Page<T>(
    @SerialName("data") public val data: List<T>,
    @SerialName("list_metadata") public val listMetadata: ListMetadata = ListMetadata(),
)
