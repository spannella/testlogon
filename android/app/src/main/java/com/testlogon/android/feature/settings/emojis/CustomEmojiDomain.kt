package com.testlogon.android.feature.settings.emojis

/** Framework-free domain model for a personal custom emoji (mirrors the web CustomEmojisPage). */
data class CustomEmoji(
    val emojiId: String,
    val shortcode: String,
    val name: String,
    val imageUrl: String?,
    val altText: String,
    val category: String,
    val ownerScope: String,
)

/** Bytes + metadata for a multipart emoji upload (kept Android-free so the repo is JVM-testable). */
data class EmojiUpload(
    val shortcode: String,
    val name: String,
    val altText: String,
    val category: String,
    val bytes: ByteArray,
    val contentType: String,
    val fileName: String,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is EmojiUpload &&
                shortcode == other.shortcode &&
                name == other.name &&
                altText == other.altText &&
                category == other.category &&
                bytes.contentEquals(other.bytes) &&
                contentType == other.contentType &&
                fileName == other.fileName
            )

    override fun hashCode(): Int {
        var result = shortcode.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + altText.hashCode()
        result = 31 * result + category.hashCode()
        result = 31 * result + bytes.contentHashCode()
        result = 31 * result + contentType.hashCode()
        result = 31 * result + fileName.hashCode()
        return result
    }
}
