"""Errors that map directly to HTTP responses."""

from __future__ import annotations


class RequestError(Exception):
    """A client-visible error; `message` must never contain request payload values."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
