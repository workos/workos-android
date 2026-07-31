// @oagen-ignore-file
package com.workos.android.internal

import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Request-body builder. Generated methods either accumulate named fields via [set],
 * or hand over a whole object via [setRaw] / [setRawJson] when the operation's body
 * is a field-less model or a non-object schema that cannot be flattened into
 * parameters.
 */
public class JsonBody {
    private val fields = LinkedHashMap<String, JsonElement>()
    private var rawElement: JsonElement? = null

    /** Add one field. Ignores null — that is how optional body fields are omitted. */
    public fun set(
        key: String,
        value: Any?,
    ) {
        if (value == null) return
        fields[key] = convert(value)
    }

    /** Replace the whole body with a serialized object, using a compile-time serializer. */
    public fun <T> setRaw(
        serializer: SerializationStrategy<T>,
        value: T,
    ) {
        rawElement = workosJson.encodeToJsonElement(serializer, value)
    }

    /** Replace the whole body with a pre-built element. */
    public fun setRawJson(value: JsonElement) {
        rawElement = value
    }

    public fun toJsonElement(): JsonElement = rawElement ?: JsonObject(fields)

    private fun convert(value: Any): JsonElement =
        when (value) {
            is JsonElement -> value
            is String -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            is ByteArray ->
                JsonPrimitive(
                    java.util.Base64
                        .getEncoder()
                        .encodeToString(value),
                )
            is List<*> -> JsonArray(value.filterNotNull().map { convert(it) })
            is Map<*, *> ->
                JsonObject(
                    value.entries
                        .filter { it.key != null && it.value != null }
                        .associate { it.key.toString() to convert(it.value!!) },
                )
            // Generated enums are sealed classes carrying the wire value in `rawValue`;
            // toString() would emit the object name ("Active" instead of "active").
            else -> JsonPrimitive(rawValueOf(value) ?: value.toString())
        }

    private fun rawValueOf(value: Any): String? =
        try {
            value.javaClass
                .getMethod("getRawValue")
                .invoke(value)
                ?.toString()
        } catch (e: ReflectiveOperationException) {
            null
        }
}

/** A single query parameter. Arrays are expressed as repeated entries. */
public data class QueryParam(
    public val name: String,
    public val value: String,
)
