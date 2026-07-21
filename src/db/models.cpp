#include "db/models.h"

json User::toJson() const {
    return {
        {"id", id},
        {"email", email},
        {"displayName", display_name},
        {"createdAt", created_at}
    };
}

json ApiKeyInfo::toJson() const {
    return {
        {"id", id},
        {"name", name},
        {"prefix", prefix},
        {"createdAt", created_at},
        {"lastUsedAt", last_used_at}
    };
}

json FileMeta::toJson() const {
    return {
        {"id", id},
        {"type", "file"},
        {"folderId", folder_id},
        {"name", name},
        {"mime", mime},
        {"size", size},
        {"createdAt", created_at},
        {"starred", starred},
        {"wrappedKey", wrapped_key},
        {"encName", enc_name}
    };
}

json Folder::toJson() const {
    return {
        {"id", id},
        {"type", "folder"},
        {"parentId", parent_id},
        {"name", name},
        {"createdAt", created_at},
        {"starred", starred},
        {"encName", enc_name}
    };
}

json Note::toJson() const {
    return {
        {"id", id},
        {"title", title},
        {"body", body},
        {"createdAt", created_at},
        {"updatedAt", updated_at}
    };
}

json Note::toSummaryJson() const {
    return {
        {"id", id},
        {"title", title},
        {"createdAt", created_at},
        {"updatedAt", updated_at}
    };
}
