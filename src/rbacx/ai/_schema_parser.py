"""OpenAPI schema parsing: normalise any supported format into NormalizedSchema."""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rbacx.ai.exceptions import SchemaParseError

# ---------------------------------------------------------------------------
# HTTP method → logical action mapping (class-level, overrideable per parser)
# ---------------------------------------------------------------------------

METHOD_TO_ACTION: dict[str, str] = {
    "GET": "read",
    "POST": "create",
    "PUT": "replace",
    "PATCH": "update",
    "DELETE": "delete",
}

# Header parameter name fragments that signal authentication
_AUTH_HEADER_FRAGMENTS: frozenset[str] = frozenset(
    {"token", "auth", "secret", "key", "authorization"}
)


# ---------------------------------------------------------------------------
# Normalised data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizedEndpoint:
    """A single API operation normalised from any supported schema format.

    Attributes:
        path: raw path string, e.g. ``/tasks/{id}``.
        method: uppercase HTTP method, e.g. ``"GET"``.
        resource_type: logical resource name derived from the operation's first
                       OpenAPI tag; falls back to the first non-empty path
                       segment when no tags are present.
        action: logical action mapped from *method* via ``METHOD_TO_ACTION``.
        summary: short operation summary or ``None``.
        description: longer operation description or ``None``.
        requires_auth: ``True`` when at least one *required* header parameter
                       has a name that contains an auth-related fragment
                       (case-insensitive match against ``_AUTH_HEADER_FRAGMENTS``).
        error_codes: sorted list of non-2xx HTTP status codes declared in the
                     operation's ``responses`` object — useful as LLM hints for
                     generating conditions (e.g. 402 → limit check, 403 →
                     ownership condition).
    """

    path: str
    method: str
    resource_type: str
    action: str
    summary: str | None
    description: str | None
    requires_auth: bool
    error_codes: list[int]


@dataclass(frozen=True)
class NormalizedSchema:
    """Schema normalised from OpenAPI 3.x or 2.0 input.

    Attributes:
        title: API title from ``info.title``.
        version: API version string from ``info.version``.
        endpoints: list of all normalised operations across all paths.
    """

    title: str
    version: str
    endpoints: list[NormalizedEndpoint]

    def to_prompt_repr(self) -> str:
        """Return a compact, LLM-friendly text representation.

        Operations are grouped by ``resource_type``.  Each group lists the
        available actions, whether auth is required, and notable error codes.

        Example output::

            Resource: task
              Actions: read (GET /tasks), create (POST /tasks), delete (DELETE /tasks/{id})
              Auth required: yes
              Notable errors: 403 (Forbidden), 404 (Not Found)

            Resource: project
              Actions: read (GET /projects)
              Auth required: yes
              Notable errors: 401 (Unauthorized)
        """
        groups: dict[str, list[NormalizedEndpoint]] = {}
        for ep in self.endpoints:
            groups.setdefault(ep.resource_type, []).append(ep)

        lines: list[str] = []
        for resource_type, endpoints in groups.items():
            actions_str = ", ".join(f"{ep.action} ({ep.method} {ep.path})" for ep in endpoints)
            auth_required = any(ep.requires_auth for ep in endpoints)
            all_error_codes: list[int] = sorted(
                {code for ep in endpoints for code in ep.error_codes}
            )

            lines.append(f"Resource: {resource_type}")
            lines.append(f"  Actions: {actions_str}")
            lines.append(f"  Auth required: {'yes' if auth_required else 'no'}")
            if all_error_codes:
                lines.append(f"  Notable errors: {', '.join(str(c) for c in all_error_codes)}")
            lines.append("")

        return "\n".join(lines).rstrip()


# ---------------------------------------------------------------------------
# Helper utilities shared by parsers
# ---------------------------------------------------------------------------


def _resource_type_from_tags(tags: list[Any], path: str) -> str:
    """Return the resource type from tags or derive it from the path."""
    if tags and isinstance(tags[0], str) and tags[0].strip():
        return tags[0].strip().lower()
    # Fallback: first non-empty path segment, stripped of leading slash
    segments = [s for s in path.strip("/").split("/") if s and not s.startswith("{")]
    return segments[0].lower() if segments else "unknown"


def _is_auth_header(name: str, required: bool) -> bool:
    """Return True when *name* looks like an auth token header and is required."""
    if not required:
        return False
    name_lower = name.lower()
    return any(fragment in name_lower for fragment in _AUTH_HEADER_FRAGMENTS)


def _collect_error_codes(responses: dict[str, Any]) -> list[int]:
    """Return sorted non-2xx integer status codes from a responses dict."""
    codes: list[int] = []
    for status_str in responses:
        try:
            code = int(status_str)
        except (ValueError, TypeError):
            continue
        if not (200 <= code < 300):
            codes.append(code)
    return sorted(codes)


def _action_for_method(method: str) -> str:
    return METHOD_TO_ACTION.get(method.upper(), method.lower())


# ---------------------------------------------------------------------------
# Abstract parser strategy
# ---------------------------------------------------------------------------


class AbstractSchemaParser(ABC):
    """Strategy interface for schema-format-specific parsers."""

    @abstractmethod
    def can_parse(self, raw: dict[str, Any]) -> bool:
        """Return ``True`` if this parser can handle *raw*."""

    @abstractmethod
    def parse(self, raw: dict[str, Any]) -> NormalizedSchema:
        """Parse *raw* into a :class:`NormalizedSchema`.

        Raises:
            SchemaParseError: if the schema is structurally malformed.
        """


# ---------------------------------------------------------------------------
# OpenAPI 3.x parser
# ---------------------------------------------------------------------------


class OpenAPI3Parser(AbstractSchemaParser):
    """Parser for OpenAPI 3.x schemas (``openapi`` key starting with ``"3"``)."""

    def can_parse(self, raw: dict[str, Any]) -> bool:
        version = raw.get("openapi", "")
        return isinstance(version, str) and version.startswith("3")

    def parse(self, raw: dict[str, Any]) -> NormalizedSchema:
        info: dict[str, Any] = raw.get("info") or {}
        title: str = info.get("title", "Unknown API")
        version: str = info.get("version", "0.0.0")

        paths: dict[str, Any] = raw.get("paths") or {}
        endpoints: list[NormalizedEndpoint] = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method_raw, operation in path_item.items():
                method = method_raw.upper()
                if method not in METHOD_TO_ACTION or not isinstance(operation, dict):
                    continue

                tags: list[Any] = operation.get("tags") or []
                resource_type = _resource_type_from_tags(tags, path)
                parameters: list[Any] = operation.get("parameters") or []
                requires_auth = any(
                    _is_auth_header(
                        p.get("name", ""),
                        bool(p.get("required", False)),
                    )
                    for p in parameters
                    if isinstance(p, dict) and p.get("in") == "header"
                )
                responses: dict[str, Any] = operation.get("responses") or {}
                error_codes = _collect_error_codes(responses)

                endpoints.append(
                    NormalizedEndpoint(
                        path=path,
                        method=method,
                        resource_type=resource_type,
                        action=_action_for_method(method),
                        summary=operation.get("summary") or None,
                        description=operation.get("description") or None,
                        requires_auth=requires_auth,
                        error_codes=error_codes,
                    )
                )

        return NormalizedSchema(title=title, version=version, endpoints=endpoints)


# ---------------------------------------------------------------------------
# OpenAPI 2.0 (Swagger) parser
# ---------------------------------------------------------------------------


class OpenAPI2Parser(AbstractSchemaParser):
    """Parser for OpenAPI 2.0 / Swagger schemas (``swagger: "2.0"`` key)."""

    def can_parse(self, raw: dict[str, Any]) -> bool:
        return raw.get("swagger") == "2.0"

    def parse(self, raw: dict[str, Any]) -> NormalizedSchema:
        info: dict[str, Any] = raw.get("info") or {}
        title: str = info.get("title", "Unknown API")
        version: str = info.get("version", "0.0.0")

        paths: dict[str, Any] = raw.get("paths") or {}
        endpoints: list[NormalizedEndpoint] = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method_raw, operation in path_item.items():
                method = method_raw.upper()
                if method not in METHOD_TO_ACTION or not isinstance(operation, dict):
                    continue

                tags: list[Any] = operation.get("tags") or []
                resource_type = _resource_type_from_tags(tags, path)

                # In OpenAPI 2.0 parameters are a flat list on the operation
                parameters: list[Any] = operation.get("parameters") or []
                requires_auth = any(
                    _is_auth_header(
                        p.get("name", ""),
                        bool(p.get("required", False)),
                    )
                    for p in parameters
                    if isinstance(p, dict) and p.get("in") == "header"
                )
                responses: dict[str, Any] = operation.get("responses") or {}
                error_codes = _collect_error_codes(responses)

                endpoints.append(
                    NormalizedEndpoint(
                        path=path,
                        method=method,
                        resource_type=resource_type,
                        action=_action_for_method(method),
                        summary=operation.get("summary") or None,
                        description=operation.get("description") or None,
                        requires_auth=requires_auth,
                        error_codes=error_codes,
                    )
                )

        return NormalizedSchema(title=title, version=version, endpoints=endpoints)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


class SchemaParser:
    """Auto-detecting schema parser.

    Accepts a file path (JSON or YAML), a raw JSON string, or a pre-loaded
    dict.  Delegates to the first :class:`AbstractSchemaParser` whose
    :meth:`can_parse` returns ``True``.

    Supported formats (in detection order):

    * OpenAPI 3.x (``openapi: "3.x.x"``)
    * OpenAPI 2.0 / Swagger (``swagger: "2.0"``)
    """

    _parsers: list[AbstractSchemaParser] = [
        OpenAPI3Parser(),
        OpenAPI2Parser(),
    ]

    @classmethod
    def parse(cls, source: Path | str | dict[str, Any]) -> NormalizedSchema:
        """Parse *source* into a :class:`NormalizedSchema`.

        Args:
            source: one of:

                * :class:`pathlib.Path` — path to a ``.json`` or ``.yaml``/
                  ``.yml`` file.
                * :class:`str` — either a file-system path string or raw JSON.
                * :class:`dict` — pre-loaded schema dict (passed through
                  without any file I/O).

        Returns:
            :class:`NormalizedSchema` ready to be rendered as a prompt.

        Raises:
            SchemaParseError: if the file cannot be read, the content cannot
                              be decoded as JSON/YAML, or no registered parser
                              recognises the schema format.
        """
        raw = cls._load(source)
        for parser in cls._parsers:
            if parser.can_parse(raw):
                return parser.parse(raw)
        detected = (
            f"openapi={raw.get('openapi')!r}"
            if "openapi" in raw
            else f"swagger={raw.get('swagger')!r}"
            if "swagger" in raw
            else "unknown"
        )
        raise SchemaParseError(
            f"Unrecognised schema format ({detected}). "
            "Supported formats: OpenAPI 3.x, OpenAPI 2.0 (Swagger).",
            format_hint=detected,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @classmethod
    def _load(cls, source: Path | str | dict[str, Any]) -> dict[str, Any]:
        """Resolve *source* to a plain dict."""
        if isinstance(source, dict):
            return source

        path: Path | None = None
        if isinstance(source, Path):
            path = source
        elif isinstance(source, str):
            # Heuristic: if it looks like a file path, treat it as one
            candidate = Path(source)
            if candidate.suffix.lower() in {".json", ".yaml", ".yml"} or candidate.exists():
                path = candidate
            else:
                # Try to parse as raw JSON string
                return cls._parse_json_str(source)

        if path is not None:
            return cls._read_file(path)

        raise SchemaParseError(
            f"Cannot resolve source to a schema: {source!r}",
            format_hint=None,
        )

    @staticmethod
    def _read_file(path: Path) -> dict[str, Any]:
        """Read and decode a JSON or YAML file."""
        if not path.exists():
            raise SchemaParseError(
                f"Schema file not found: {path}",
                format_hint=None,
            )
        text = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()
        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:
                raise SchemaParseError(
                    "PyYAML is required to parse YAML schemas. "
                    "Install it with: pip install rbacx[ai]",
                    format_hint="yaml",
                ) from exc
            try:
                data = yaml.safe_load(text)
            except Exception as exc:
                raise SchemaParseError(
                    f"Failed to parse YAML file {path}: {exc}",
                    format_hint="yaml",
                ) from exc
        else:
            data = SchemaParser._parse_json_str(text, hint=str(path))

        if not isinstance(data, dict):
            raise SchemaParseError(
                f"Schema must be a JSON/YAML object, got {type(data).__name__}",
                format_hint=None,
            )
        return data

    @staticmethod
    def _parse_json_str(text: str, hint: str = "<string>") -> dict[str, Any]:
        """Parse a raw JSON string into a dict."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SchemaParseError(
                f"Failed to parse JSON from {hint}: {exc}",
                format_hint="json",
            ) from exc
        if not isinstance(data, dict):
            raise SchemaParseError(
                f"Schema must be a JSON object, got {type(data).__name__}",
                format_hint="json",
            )
        return data
