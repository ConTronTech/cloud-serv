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
        {"name", name},
        {"mime", mime},
        {"size", size},
        {"createdAt", created_at}
    };
}
