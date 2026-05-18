from __future__ import annotations

from typing import Final, Tuple

# Canonical message linkage field names shared across write/read paths.
#
# Semantics:
# - reply_to_message_id: compatibility field for existing clients that reply to a specific
#   message id (legacy external API surface).
# - parent_message_id: normalized immediate-parent message id used for reply-tree traversal.
#   For direct replies this equals reply_to_message_id.
# - thread_id: stable identifier of the breakout thread once a subtree is promoted.
# - thread_root_message_id: top-level root message id anchoring all messages in the thread.
MESSAGE_FIELD_REPLY_TO_ID: Final[str] = "reply_to_message_id"
MESSAGE_FIELD_PARENT_ID: Final[str] = "parent_message_id"
MESSAGE_FIELD_THREAD_ID: Final[str] = "thread_id"
MESSAGE_FIELD_THREAD_ROOT_ID: Final[str] = "thread_root_message_id"

# Thread persistence contract fields.
THREAD_FIELD_ID: Final[str] = "id"
THREAD_FIELD_CONVERSATION_ID: Final[str] = "conversation_id"
THREAD_FIELD_ROOT_MESSAGE_ID: Final[str] = "root_message_id"
THREAD_FIELD_CREATED_AT: Final[str] = "created_at"
THREAD_FIELD_CREATED_BY: Final[str] = "created_by"
THREAD_REQUIRED_FIELDS: Final[Tuple[str, ...]] = (
    THREAD_FIELD_ID,
    THREAD_FIELD_CONVERSATION_ID,
    THREAD_FIELD_ROOT_MESSAGE_ID,
    THREAD_FIELD_CREATED_AT,
    THREAD_FIELD_CREATED_BY,
)

# Canonical thread lifecycle states for future promotion/business logic.
THREAD_STATE_INLINE: Final[str] = "inline"
THREAD_STATE_PROMOTED: Final[str] = "promoted"
THREAD_STATE_RECONCILING: Final[str] = "reconciling"
THREAD_STATE_ARCHIVED: Final[str] = "archived"
THREAD_STATES: Final[Tuple[str, ...]] = (
    THREAD_STATE_INLINE,
    THREAD_STATE_PROMOTED,
    THREAD_STATE_RECONCILING,
    THREAD_STATE_ARCHIVED,
)

# Index names for thread/query access patterns.
INDEX_BY_CONVERSATION_CREATED_AT: Final[str] = "ByConversationCreatedAt"
INDEX_BY_PARENT_MESSAGE_ID: Final[str] = "ByParentMessageId"
INDEX_BY_THREAD_CREATED_AT: Final[str] = "ByThreadCreatedAt"
INDEX_BY_THREAD_ROOT_MESSAGE_ID: Final[str] = "ByThreadRootMessageId"
INDEX_BY_ROOT_MESSAGE: Final[str] = "ByRootMessage"
