// @oagen-ignore-file
package com.workos.android.internal

import com.workos.android.Page
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * Drives a cursor-paginated call across every page. Generated `…AutoPaging` methods
 * delegate here; §4 of the runtime contract requires auto-pagination to actually
 * fetch subsequent pages rather than just expose the cursor.
 */
public fun <T> autoPagingFlow(fetch: suspend (String?) -> Page<T>): Flow<T> =
    flow {
        var cursor: String? = null
        while (true) {
            val page = fetch(cursor)
            for (item in page.data) emit(item)
            cursor = page.listMetadata.after ?: break
        }
    }
