#include "db/models.h"

json User::toJson() const {
    return {
        {"id", id},
        {"email", email},
        {"displayName", display_name},
        {"createdAt", created_at},
        {"role", role},
        {"status", status}
    };
}

json User::toAdminJson(int64_t usedBytes, int64_t fileCount) const {
    json j = toJson();
    j["storageUsedBytes"] = usedBytes;
    j["fileCount"] = fileCount;
    j["storageQuotaBytes"] = storage_quota_bytes.has_value() ? json(*storage_quota_bytes) : json(nullptr);
    return j;
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
        {"encName", enc_name},
        {"encMime", enc_mime}
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
        {"encTitle", enc_title},
        {"encBody", enc_body},
        {"createdAt", created_at},
        {"updatedAt", updated_at}
    };
}

json Note::toSummaryJson() const {
    return {
        {"id", id},
        {"title", title},
        {"encTitle", enc_title},
        {"createdAt", created_at},
        {"updatedAt", updated_at}
    };
}

json RemovedUser::toJson() const {
    return {
        {"id", id},
        {"originalUserId", original_user_id},
        {"email", email},
        {"displayName", display_name},
        {"removedAt", removed_at},
        {"removedBy", removed_by}
        // backup_path intentionally omitted — a filesystem path is an internal
        // detail, not something a client needs.
    };
}
