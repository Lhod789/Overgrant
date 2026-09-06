from enum import IntEnum


class Breadth(IntEnum):
    SELF = 1
    RESOURCE = 2
    WORKSPACE = 3
    ORG_ADMIN = 4


class Mutability(IntEnum):
    READ = 1
    WRITE = 2
    DELETE = 3
    ADMIN = 4


class Sensitivity(IntEnum):
    NONE = 1
    METADATA = 2
    CONTENT = 3
    CREDENTIALS = 4


DATA_CLASSES = frozenset(
    {
        "messages",
        "direct_messages",
        "mailbox",
        "email_address",
        "files",
        "calendar_events",
        "contacts",
        "profiles",
        "directory",
        "credentials",
        "audit_logs",
    }
)

IDENTIFIES_PEOPLE = frozenset(
    {
        "contacts",
        "profiles",
        "directory",
        "email_address",
    }
)

PRIVATE_CORRESPONDENCE = frozenset(
    {
        "direct_messages",
        "mailbox",
    }
)
