"""Typed errors used by the quarantine service."""


class QuarantineError(Exception):
    """Base class for all service errors."""


class UploadNotFound(QuarantineError):
    pass


class UploadTooLarge(QuarantineError):
    def __init__(self, size: int, limit: int):
        super().__init__(f"upload is {size} bytes; limit is {limit} bytes")
        self.size = size
        self.limit = limit


class UploadConflict(QuarantineError):
    """The same upload_id was reused with different content."""

    def __init__(self, upload_id: str, existing_content: str, requested_content: str):
        super().__init__(
            f"upload_id {upload_id!r} already refers to content {existing_content}; "
            f"refusing different content {requested_content}"
        )
        self.upload_id = upload_id
        self.existing_content = existing_content
        self.requested_content = requested_content


class CsvValidationError(QuarantineError):
    """A staged CSV violates the fixed import contract."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        message = code if not detail else f"{code}: {detail}"
        super().__init__(message)


class ObjectIntegrityError(QuarantineError):
    """A managed object no longer matches its content address."""
