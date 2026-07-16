#!/usr/bin/env python3
"""MODX WAVE-2 Android app edits (report call-sites + data layer for the new surfaces)."""
import sys

BASE = "app/src/main/java/com/testlogon/android/"
RF = BASE + "data/report/ReportFlow.kt"
API = BASE + "data/report/ModerationReportApi.kt"
REPO = BASE + "data/report/ReportFlowRepository.kt"
SYND = BASE + "feature/syndicates/ui/SyndicateOverviewScreen.kt"
CHAT = BASE + "feature/broadcast/chat/LiveChatPanel.kt"
SHELF = BASE + "feature/broadcast/shelf/ProductsShelf.kt"


def patch(path, edits, allow_multi=False):
    s = open(path, encoding="utf-8").read()
    ok = True
    for a, b, guard in edits:
        if guard in s:
            print("  already applied:", path, "::", guard[:56])
            continue
        n = s.count(a)
        if allow_multi:
            if n == 0:
                print("  ANCHOR MISS (0)", path, "::", a[:56]); ok = False; continue
        elif n != 1:
            print("  ANCHOR MISS (%d)" % n, path, "::", a[:56]); ok = False; continue
        s = s.replace(a, b)
    open(path, "w", encoding="utf-8").write(s)
    return ok


ok = True

# ── ReportFlow.kt ─────────────────────────────────────────────────────────────
RF_CONTENT_A = "    data class Content(override val id: String, val contentType: String) : ReportTarget"
RF_CONTENT_B = """    data class Content(
        override val id: String,
        val contentType: String,
        val syndicateId: String? = null,
        val categoryId: String? = null,
        val itemId: String? = null,
        val sessionId: String? = null,
    ) : ReportTarget"""

RF_USER_A = "    data class User(override val id: String, val displayName: String? = null) : ReportTarget"
RF_USER_B = """    data class User(override val id: String, val displayName: String? = null) : ReportTarget

    /** MODX-11 - account-level report (content_type=user), keyed on the user; no profile photo required. */
    data class Account(override val id: String, val displayName: String? = null) : ReportTarget"""

RF_KIND_A = """        is ReportTarget.User -> ReportKind.USER
        is ReportTarget.Content -> ReportKind.CONTENT
        is ReportTarget.Message -> ReportKind.MESSAGE
    }"""
RF_KIND_B = """        is ReportTarget.User -> ReportKind.USER
        is ReportTarget.Account -> ReportKind.USER
        is ReportTarget.Content -> ReportKind.CONTENT
        is ReportTarget.Message -> ReportKind.MESSAGE
    }"""

RF_MCT_A = """    is ReportTarget.User -> "profile_photo"
    is ReportTarget.Content -> contentType"""
RF_MCT_B = """    is ReportTarget.User -> "profile_photo"
    is ReportTarget.Account -> "user"
    is ReportTarget.Content -> contentType"""

print("ReportFlow.kt:")
ok &= patch(RF, [
    (RF_CONTENT_A, RF_CONTENT_B, "val syndicateId: String? = null"),
    (RF_USER_A, RF_USER_B, "data class Account(override val id"),
    (RF_KIND_A, RF_KIND_B, "is ReportTarget.Account -> ReportKind.USER"),
    (RF_MCT_A, RF_MCT_B, 'is ReportTarget.Account -> "user"'),
])

# ── ModerationReportApi.kt (DTO) ──────────────────────────────────────────────
API_A = '    @Json(name = "profile_user_id") val profileUserId: String? = null,\n)'
API_B = ('    @Json(name = "profile_user_id") val profileUserId: String? = null,\n'
         '    @Json(name = "syndicate_id") val syndicateId: String? = null,\n'
         '    @Json(name = "category_id") val categoryId: String? = null,\n'
         '    @Json(name = "item_id") val itemId: String? = null,\n'
         '    @Json(name = "session_id") val sessionId: String? = null,\n)')
print("ModerationReportApi.kt:")
ok &= patch(API, [(API_A, API_B, '@Json(name = "syndicate_id") val syndicateId')])

# ── ReportFlowRepository.kt ───────────────────────────────────────────────────
REPO_WHEN_A = """        when (target) {
            is ReportTarget.Message -> submitMessage(target, topics, reasonText)
            is ReportTarget.User -> submitModeration(target, topics, reasonText)
            is ReportTarget.Content -> submitModeration(target, topics, reasonText)
        }"""
REPO_WHEN_B = """        when (target) {
            is ReportTarget.Message -> submitMessage(target, topics, reasonText)
            is ReportTarget.User -> submitModeration(target, topics, reasonText)
            is ReportTarget.Account -> submitModeration(target, topics, reasonText)
            is ReportTarget.Content -> submitModeration(target, topics, reasonText)
        }"""

REPO_BUILD_A = """        return when (target) {
            is ReportTarget.User -> base.copy(profileUserId = target.id)
            is ReportTarget.Content -> when (target.contentType) {
                "feed_comment" -> base.copy(commentId = target.id)
                else -> base.copy(postId = target.id)
            }
            is ReportTarget.Message -> base // unreachable (routed to the message endpoint)
        }"""
REPO_BUILD_B = """        return when (target) {
            is ReportTarget.User -> base.copy(profileUserId = target.id)
            is ReportTarget.Account -> base.copy(profileUserId = target.id)
            is ReportTarget.Content -> {
                val withIds = base.copy(
                    syndicateId = target.syndicateId,
                    categoryId = target.categoryId,
                    itemId = target.itemId,
                    sessionId = target.sessionId,
                )
                when (target.contentType) {
                    "feed_comment" -> withIds.copy(commentId = target.id)
                    "catalog_item", "catalog_review", "broadcast_message", "story", "clip" -> withIds
                    else -> withIds.copy(postId = target.id)
                }
            }
            is ReportTarget.Message -> base // unreachable (routed to the message endpoint)
        }"""
print("ReportFlowRepository.kt:")
ok &= patch(REPO, [
    (REPO_WHEN_A, REPO_WHEN_B, "is ReportTarget.Account -> submitModeration"),
    (REPO_BUILD_A, REPO_BUILD_B, "val withIds = base.copy("),
])

# ── SyndicateOverviewScreen.kt (the B1 bug) ───────────────────────────────────
SYND_A = '        LocalSyndicateReport provides { post -> reportTarget = ReportTarget.Content(post.postId, "feed_post") },'
SYND_B = '        LocalSyndicateReport provides { post -> reportTarget = ReportTarget.Content(post.postId, "syndicate_post", syndicateId = viewModel.syndicateId) },'
print("SyndicateOverviewScreen.kt:")
ok &= patch(SYND, [(SYND_A, SYND_B, '"syndicate_post", syndicateId = viewModel.syndicateId')])

# ── LiveChatPanel.kt (broadcast_message report) ───────────────────────────────
CHAT_IMPORT_A = "import androidx.compose.runtime.setValue"
CHAT_IMPORT_B = ("import androidx.compose.runtime.setValue\n"
                 "import com.testlogon.android.data.report.ReportTarget\n"
                 "import com.testlogon.android.feature.report.ContentReportSheetHost")
CHAT_STATE_A = """    // Message-actions sheet (long-press): react + reply.
    var actionTarget by remember { mutableStateOf<ChatMessage?>(null) }"""
CHAT_STATE_B = """    // Message-actions sheet (long-press): react + reply.
    var actionTarget by remember { mutableStateOf<ChatMessage?>(null) }
    // MODX-12 - live-chat message report target.
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }"""
CHAT_BTN_A = """                    Text(stringResource(R.string.live_chat_reply), modifier = Modifier.padding(start = 8.dp))
                }
            }
        }
    }"""
CHAT_BTN_B = """                    Text(stringResource(R.string.live_chat_reply), modifier = Modifier.padding(start = 8.dp))
                }
                if (!target.isSelf) {
                    TextButton(
                        onClick = {
                            reportTarget = ReportTarget.Content(target.id, "broadcast_message", sessionId = target.sessionId)
                            actionTarget = null
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.msg_action_report), modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        }
    }

    // MODX-12 - live-chat message report (viewer -> the moderation state machine).
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })"""
print("LiveChatPanel.kt:")
ok &= patch(CHAT, [
    (CHAT_IMPORT_A, CHAT_IMPORT_B, "import com.testlogon.android.feature.report.ContentReportSheetHost"),
    (CHAT_STATE_A, CHAT_STATE_B, "live-chat message report target"),
    (CHAT_BTN_A, CHAT_BTN_B, "broadcast_message"),
])

# ── ProductsShelf.kt (catalog_item report) ────────────────────────────────────
SHELF_IMPORT_A = "import androidx.compose.runtime.getValue"
SHELF_IMPORT_B = ("import androidx.compose.runtime.getValue\n"
                  "import androidx.compose.runtime.mutableStateOf\n"
                  "import androidx.compose.runtime.remember\n"
                  "import androidx.compose.runtime.setValue\n"
                  "import com.testlogon.android.data.report.ReportTarget\n"
                  "import com.testlogon.android.feature.report.ContentReportSheetHost")

SHELF_PANEL_A = """    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val expanded by viewModel.expanded.collectAsStateWithLifecycle()
    ProductsShelf(
        state = state,
        expanded = expanded,
        onToggle = viewModel::setExpanded,
        onBuy = { product -> onBuy(product.categoryId, product.itemId) },
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}"""
SHELF_PANEL_B = """    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val expanded by viewModel.expanded.collectAsStateWithLifecycle()
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    ProductsShelf(
        state = state,
        expanded = expanded,
        onToggle = viewModel::setExpanded,
        onBuy = { product -> onBuy(product.categoryId, product.itemId) },
        onReport = { product ->
            reportTarget = ReportTarget.Content(
                product.itemId,
                "catalog_item",
                categoryId = product.categoryId,
                itemId = product.itemId,
            )
        },
        onRetry = viewModel::retry,
        modifier = modifier,
    )
    // MODX-12 - report a catalog product from the live shelf.
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
}"""

SHELF_SIG_A = """fun ProductsShelf(
    state: ProductsShelfUiState,
    expanded: Boolean,
    onToggle: (Boolean) -> Unit,
    onBuy: (ShelfProduct) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {"""
SHELF_SIG_B = """fun ProductsShelf(
    state: ProductsShelfUiState,
    expanded: Boolean,
    onToggle: (Boolean) -> Unit,
    onBuy: (ShelfProduct) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    onReport: (ShelfProduct) -> Unit = {},
) {"""

SHELF_READY_A = "                    is ProductsShelfUiState.Ready -> ShelfRow(state.products, onBuy)"
SHELF_READY_B = "                    is ProductsShelfUiState.Ready -> ShelfRow(state.products, onBuy, onReport)"

SHELF_ROW_A = """private fun ShelfRow(products: List<ShelfProduct>, onBuy: (ShelfProduct) -> Unit) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.ROW),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(products, key = { it.itemId }) { product ->
            ProductShelfCard(product = product, onBuy = { onBuy(product) })
        }
    }
}"""
SHELF_ROW_B = """private fun ShelfRow(products: List<ShelfProduct>, onBuy: (ShelfProduct) -> Unit, onReport: (ShelfProduct) -> Unit = {}) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.ROW),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(products, key = { it.itemId }) { product ->
            ProductShelfCard(product = product, onBuy = { onBuy(product) }, onReport = { onReport(product) })
        }
    }
}"""

SHELF_CARD_A = "private fun ProductShelfCard(product: ShelfProduct, onBuy: () -> Unit) {"
SHELF_CARD_B = "private fun ProductShelfCard(product: ShelfProduct, onBuy: () -> Unit, onReport: () -> Unit = {}) {"

SHELF_BUY_A = """        Button(
            onClick = onBuy,
            modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.BUY),
        ) {
            Text(stringResource(R.string.shelf_buy))
        }
    }
}"""
SHELF_BUY_B = """        Button(
            onClick = onBuy,
            modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.BUY),
        ) {
            Text(stringResource(R.string.shelf_buy))
        }
        TextButton(
            onClick = onReport,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.msg_action_report))
        }
    }
}"""
print("ProductsShelf.kt:")
ok &= patch(SHELF, [
    (SHELF_IMPORT_A, SHELF_IMPORT_B, "import com.testlogon.android.feature.report.ContentReportSheetHost"),
    (SHELF_PANEL_A, SHELF_PANEL_B, "report a catalog product from the live shelf"),
    (SHELF_SIG_A, SHELF_SIG_B, "onReport: (ShelfProduct) -> Unit = {},"),
    (SHELF_READY_A, SHELF_READY_B, "ShelfRow(state.products, onBuy, onReport)"),
    (SHELF_ROW_A, SHELF_ROW_B, "onReport: (ShelfProduct) -> Unit = {}) {"),
    (SHELF_CARD_A, SHELF_CARD_B, "onReport: () -> Unit = {}) {"),
    (SHELF_BUY_A, SHELF_BUY_B, "onClick = onReport,"),
])

print("RESULT:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
