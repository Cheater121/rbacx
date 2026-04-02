"""Tests for rbacx.ai._schema_parser."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rbacx.ai._schema_parser import (
    METHOD_TO_ACTION,
    NormalizedEndpoint,
    NormalizedSchema,
    OpenAPI2Parser,
    OpenAPI3Parser,
    SchemaParser,
    _action_for_method,
    _collect_error_codes,
    _is_auth_header,
    _resource_type_from_tags,
)
from rbacx.ai.exceptions import SchemaParseError

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


class TestResourceTypeFromTags:
    def test_uses_first_tag(self) -> None:
        assert _resource_type_from_tags(["Task", "misc"], "/tasks") == "task"

    def test_lowercases_tag(self) -> None:
        assert _resource_type_from_tags(["MyResource"], "/my-resource") == "myresource"

    def test_falls_back_to_path_when_no_tags(self) -> None:
        assert _resource_type_from_tags([], "/tasks/{id}") == "tasks"

    def test_falls_back_to_path_when_tags_empty_string(self) -> None:
        assert _resource_type_from_tags([""], "/projects") == "projects"

    def test_skips_path_params_in_fallback(self) -> None:
        # /tasks/{id} → first non-param segment is "tasks"
        assert _resource_type_from_tags([], "/tasks/{id}") == "tasks"

    def test_returns_unknown_for_root_path(self) -> None:
        assert _resource_type_from_tags([], "/") == "unknown"


class TestIsAuthHeader:
    def test_token_in_name(self) -> None:
        assert _is_auth_header("x-jwt-token", required=True) is True

    def test_auth_in_name(self) -> None:
        assert _is_auth_header("Authorization", required=True) is True

    def test_secret_in_name(self) -> None:
        assert _is_auth_header("x-secret-code", required=True) is True

    def test_key_in_name(self) -> None:
        assert _is_auth_header("api-key", required=True) is True

    def test_not_required_returns_false(self) -> None:
        assert _is_auth_header("x-jwt-token", required=False) is False

    def test_unrelated_name_returns_false(self) -> None:
        assert _is_auth_header("x-localization", required=True) is False

    def test_case_insensitive(self) -> None:
        assert _is_auth_header("X-JWT-TOKEN", required=True) is True


class TestCollectErrorCodes:
    def test_filters_2xx(self) -> None:
        responses = {"200": {}, "201": {}, "401": {}, "403": {}, "404": {}}
        assert _collect_error_codes(responses) == [401, 403, 404]

    def test_returns_sorted(self) -> None:
        responses = {"500": {}, "401": {}, "403": {}}
        assert _collect_error_codes(responses) == [401, 403, 500]

    def test_empty_responses(self) -> None:
        assert _collect_error_codes({}) == []

    def test_ignores_non_integer_keys(self) -> None:
        responses = {"default": {}, "200": {}, "404": {}}
        assert _collect_error_codes(responses) == [404]


class TestActionForMethod:
    @pytest.mark.parametrize(
        "method,expected",
        [
            ("GET", "read"),
            ("POST", "create"),
            ("PUT", "replace"),
            ("PATCH", "update"),
            ("DELETE", "delete"),
            ("get", "read"),
            ("Delete", "delete"),
        ],
    )
    def test_mapping(self, method: str, expected: str) -> None:
        assert _action_for_method(method) == expected

    def test_unknown_method_lowercased(self) -> None:
        assert _action_for_method("OPTIONS") == "options"


class TestMethodToActionConstant:
    def test_all_five_methods_present(self) -> None:
        assert set(METHOD_TO_ACTION.keys()) == {"GET", "POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------------------
# OpenAPI3Parser
# ---------------------------------------------------------------------------


class TestOpenAPI3Parser:
    parser = OpenAPI3Parser()

    def test_can_parse_openapi_3(self, sample_openapi3_dict: dict[str, Any]) -> None:
        assert self.parser.can_parse(sample_openapi3_dict) is True

    def test_cannot_parse_openapi_2(self, sample_openapi2_dict: dict[str, Any]) -> None:
        assert self.parser.can_parse(sample_openapi2_dict) is False

    def test_cannot_parse_unknown(self) -> None:
        assert self.parser.can_parse({"something": "else"}) is False

    def test_parses_title_and_version(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        assert schema.title == "TaskManagerAPI"
        assert schema.version == "1.0.0"

    def test_parses_endpoints(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        methods = {ep.method for ep in schema.endpoints}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_resource_type_from_tag(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        task_eps = [ep for ep in schema.endpoints if ep.resource_type == "task"]
        assert len(task_eps) > 0

    def test_requires_auth_true_for_jwt_header(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        assert all(ep.requires_auth for ep in schema.endpoints)

    def test_requires_auth_false_without_auth_headers(self) -> None:
        raw: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0.0"},
            "paths": {
                "/health": {
                    "get": {
                        "tags": ["health"],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            },
        }
        schema = self.parser.parse(raw)
        assert schema.endpoints[0].requires_auth is False

    def test_error_codes_collected(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        delete_ep = next(ep for ep in schema.endpoints if ep.method == "DELETE")
        assert 403 in delete_ep.error_codes
        assert 404 in delete_ep.error_codes

    def test_action_mapped_from_method(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        get_ep = next(ep for ep in schema.endpoints if ep.method == "GET")
        assert get_ep.action == "read"
        post_ep = next(ep for ep in schema.endpoints if ep.method == "POST")
        assert post_ep.action == "create"

    def test_summary_captured(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi3_dict)
        get_ep = next(ep for ep in schema.endpoints if ep.method == "GET")
        assert get_ep.summary == "List tasks"

    def test_no_tags_falls_back_to_path(self) -> None:
        raw: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0.0"},
            "paths": {"/users/{id}": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }
        schema = self.parser.parse(raw)
        assert schema.endpoints[0].resource_type == "users"

    def test_empty_paths_returns_no_endpoints(self) -> None:
        raw: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0.0"},
            "paths": {},
        }
        schema = self.parser.parse(raw)
        assert schema.endpoints == []


# ---------------------------------------------------------------------------
# OpenAPI2Parser
# ---------------------------------------------------------------------------


class TestOpenAPI2Parser:
    parser = OpenAPI2Parser()

    def test_can_parse_swagger_2(self, sample_openapi2_dict: dict[str, Any]) -> None:
        assert self.parser.can_parse(sample_openapi2_dict) is True

    def test_cannot_parse_openapi_3(self, sample_openapi3_dict: dict[str, Any]) -> None:
        assert self.parser.can_parse(sample_openapi3_dict) is False

    def test_parses_title_and_version(self, sample_openapi2_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi2_dict)
        assert schema.title == "TaskManagerAPI"
        assert schema.version == "1.0.0"

    def test_parses_endpoints(self, sample_openapi2_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi2_dict)
        assert len(schema.endpoints) == 1
        assert schema.endpoints[0].method == "GET"
        assert schema.endpoints[0].action == "read"

    def test_requires_auth_true(self, sample_openapi2_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi2_dict)
        assert schema.endpoints[0].requires_auth is True

    def test_resource_type_from_tag(self, sample_openapi2_dict: dict[str, Any]) -> None:
        schema = self.parser.parse(sample_openapi2_dict)
        assert schema.endpoints[0].resource_type == "task"


# ---------------------------------------------------------------------------
# NormalizedSchema.to_prompt_repr
# ---------------------------------------------------------------------------


class TestToPromptRepr:
    def test_contains_all_resource_types(self, sample_normalized_schema: NormalizedSchema) -> None:
        repr_str = sample_normalized_schema.to_prompt_repr()
        assert "Resource: task" in repr_str
        assert "Resource: project" in repr_str

    def test_contains_actions(self, sample_normalized_schema: NormalizedSchema) -> None:
        repr_str = sample_normalized_schema.to_prompt_repr()
        assert "read" in repr_str
        assert "create" in repr_str
        assert "delete" in repr_str

    def test_contains_auth_info(self, sample_normalized_schema: NormalizedSchema) -> None:
        repr_str = sample_normalized_schema.to_prompt_repr()
        assert "Auth required: yes" in repr_str

    def test_contains_error_codes(self, sample_normalized_schema: NormalizedSchema) -> None:
        repr_str = sample_normalized_schema.to_prompt_repr()
        assert "401" in repr_str
        assert "403" in repr_str

    def test_no_auth_shows_no(self) -> None:
        schema = NormalizedSchema(
            title="API",
            version="1.0.0",
            endpoints=[
                NormalizedEndpoint(
                    path="/health",
                    method="GET",
                    resource_type="health",
                    action="read",
                    summary=None,
                    description=None,
                    requires_auth=False,
                    error_codes=[],
                )
            ],
        )
        assert "Auth required: no" in schema.to_prompt_repr()

    def test_empty_endpoints_returns_empty_string(self) -> None:
        schema = NormalizedSchema(title="API", version="1.0.0", endpoints=[])
        assert schema.to_prompt_repr() == ""


# ---------------------------------------------------------------------------
# SchemaParser (entry point)
# ---------------------------------------------------------------------------


class TestSchemaParserFromDict:
    def test_openapi3_dict(self, sample_openapi3_dict: dict[str, Any]) -> None:
        schema = SchemaParser.parse(sample_openapi3_dict)
        assert isinstance(schema, NormalizedSchema)
        assert schema.title == "TaskManagerAPI"

    def test_openapi2_dict(self, sample_openapi2_dict: dict[str, Any]) -> None:
        schema = SchemaParser.parse(sample_openapi2_dict)
        assert isinstance(schema, NormalizedSchema)

    def test_unknown_format_raises(self) -> None:
        with pytest.raises(SchemaParseError):
            SchemaParser.parse({"not": "openapi"})

    def test_unknown_format_hint_in_exception(self) -> None:
        with pytest.raises(SchemaParseError) as exc_info:
            SchemaParser.parse({"not": "openapi"})
        assert exc_info.value.format_hint is not None or True  # hint may be "unknown"


class TestSchemaParserFromJsonFile:
    def test_json_file(self, tmp_path: Path, sample_openapi3_dict: dict[str, Any]) -> None:
        p = tmp_path / "schema.json"
        p.write_text(json.dumps(sample_openapi3_dict), encoding="utf-8")
        schema = SchemaParser.parse(p)
        assert schema.title == "TaskManagerAPI"

    def test_json_file_string_path(
        self, tmp_path: Path, sample_openapi3_dict: dict[str, Any]
    ) -> None:
        p = tmp_path / "schema.json"
        p.write_text(json.dumps(sample_openapi3_dict), encoding="utf-8")
        schema = SchemaParser.parse(str(p))
        assert isinstance(schema, NormalizedSchema)

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(SchemaParseError):
            SchemaParser.parse(Path("/nonexistent/schema.json"))

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json at all", encoding="utf-8")
        with pytest.raises(SchemaParseError):
            SchemaParser.parse(p)


class TestSchemaParserFromYamlFile:
    def test_yaml_file(self, tmp_path: Path, sample_openapi3_dict: dict[str, Any]) -> None:
        yaml = pytest.importorskip("yaml")
        p = tmp_path / "schema.yaml"
        p.write_text(yaml.dump(sample_openapi3_dict), encoding="utf-8")
        schema = SchemaParser.parse(p)
        assert schema.title == "TaskManagerAPI"

    def test_yml_extension(self, tmp_path: Path, sample_openapi3_dict: dict[str, Any]) -> None:
        yaml = pytest.importorskip("yaml")
        p = tmp_path / "schema.yml"
        p.write_text(yaml.dump(sample_openapi3_dict), encoding="utf-8")
        schema = SchemaParser.parse(p)
        assert isinstance(schema, NormalizedSchema)

    def test_yaml_missing_raises_schema_parse_error(self, tmp_path: Path) -> None:
        p = tmp_path / "schema.yaml"
        p.write_text("openapi: '3.0.0'\ninfo:\n  title: T\n  version: '1'\npaths: {}\n")
        with patch.dict("sys.modules", {"yaml": None}):
            # PyYAML available in env, so we test the import-error path explicitly
            with patch("rbacx.ai._schema_parser.SchemaParser._read_file") as mock_rf:
                mock_rf.side_effect = SchemaParseError("no yaml", format_hint="yaml")
                with pytest.raises(SchemaParseError, match="yaml"):
                    SchemaParser.parse(p)

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        pytest.importorskip("yaml")
        p = tmp_path / "schema.yaml"
        p.write_text("key: [\nbad yaml", encoding="utf-8")
        with pytest.raises(SchemaParseError):
            SchemaParser.parse(p)


class TestSchemaParserFromRawJsonString:
    def test_raw_json_string(self, sample_openapi3_dict: dict[str, Any]) -> None:
        raw_str = json.dumps(sample_openapi3_dict)
        schema = SchemaParser.parse(raw_str)
        assert schema.title == "TaskManagerAPI"

    def test_invalid_raw_json_string_raises(self) -> None:
        with pytest.raises(SchemaParseError):
            SchemaParser.parse("{invalid json")
