# tests/integration/storage/test_s3_source.py
import sys
import types
import importlib.util
import pytest

from rbacx.storage.s3 import S3PolicySource

# Optional dependency guard for tests that trigger schema validation
_HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


# Fakes for the S3 client and responses
class _Body:
    def __init__(self, data):
        self._d = data
        self.closed = False

    def read(self):
        return self._d.encode("utf-8")

    def close(self):
        self.closed = True


class FakeClient:
    def __init__(self, etag="xyz", version_id="v1", checksum_sha256=None, support_attrs=True):
        self._etag = etag
        self._version_id = version_id
        self._checksum_sha256 = checksum_sha256
        self._support_attrs = support_attrs
        self.exceptions = types.SimpleNamespace(NoSuchKey=KeyError)
        self._last_body = None

    def head_object(self, Bucket, Key):
        if self._etag == "__raise_nsk__":
            raise self.exceptions.NoSuchKey("no-such-key")
        resp = {"ETag": f'"{self._etag}"'}
        if self._version_id is not None:
            resp["VersionId"] = self._version_id
        return resp

    def get_object(self, Bucket, Key):
        self._last_body = _Body('{"rules": []}')
        return {"Body": self._last_body}

    def get_object_attributes(self, Bucket, Key, ObjectAttributes):
        if not self._support_attrs:
            raise RuntimeError("GetObjectAttributes not supported")
        return {"ChecksumSHA256": self._checksum_sha256}


@pytest.mark.skipif(not _HAS_JSONSCHEMA, reason="jsonschema not installed; skipping schema-validation dependent test")
def test_s3_etag_strategy(monkeypatch):
    # Patch client builder to avoid importing boto3
    monkeypatch.setattr(
        S3PolicySource, "_build_client", staticmethod(lambda *a, **k: FakeClient(etag="abc"))
    )
    src = S3PolicySource("s3://b/k", change_detector="etag")
    assert src.etag() == "etag:abc"
    # This calls .load(), which validates via jsonschema in production path
    assert src.load()["rules"] == []


def test_s3_version_id_strategy(monkeypatch):
    monkeypatch.setattr(
        S3PolicySource,
        "_build_client",
        staticmethod(lambda *a, **k: FakeClient(etag="zzz", version_id="123")),
    )
    src = S3PolicySource("s3://b/k", change_detector="version_id")
    assert src.etag() == "vid:123"


def test_s3_version_id_fallback_to_etag_when_disabled(monkeypatch):
    # Versioning disabled -> VersionId missing -> fallback to ETag
    monkeypatch.setattr(
        S3PolicySource,
        "_build_client",
        staticmethod(lambda *a, **k: FakeClient(etag="eee", version_id=None)),
    )
    src = S3PolicySource("s3://b/k", change_detector="version_id")
    assert src.etag() == "etag:eee"


def test_s3_checksum_strategy_or_fallback(monkeypatch):
    # With checksum available
    monkeypatch.setattr(
        S3PolicySource,
        "_build_client",
        staticmethod(
            lambda *a, **k: FakeClient(etag="x", checksum_sha256="deadbeef", support_attrs=True)
        ),
    )
    src = S3PolicySource("s3://b/k", change_detector="checksum")
    assert src.etag() == "ck:sha256:deadbeef"

    # If checksum API unsupported -> fallback to ETag
    monkeypatch.setattr(
        S3PolicySource,
        "_build_client",
        staticmethod(lambda *a, **k: FakeClient(etag="fff", support_attrs=False)),
    )
    src2 = S3PolicySource("s3://b/k", change_detector="checksum")
    assert src2.etag() == "etag:fff"


def test_s3_no_such_key_returns_none(monkeypatch):
    monkeypatch.setattr(
        S3PolicySource,
        "_build_client",
        staticmethod(lambda *a, **k: FakeClient(etag="__raise_nsk__")),
    )
    src = S3PolicySource("s3://b/k", change_detector="etag")
    assert src.etag() is None


def test_s3_load_closes_body_and_validates_when_enabled(monkeypatch):
    # Fake client that tracks body.close()
    fc = FakeClient()

    # Inject fake validator module to avoid importing jsonschema
    mod = types.ModuleType("rbacx.dsl.validate")
    flag = {"called": False}

    def validate_policy(policy):
        flag["called"] = True

    mod.validate_policy = validate_policy  # type: ignore[attr-defined]
    sys.modules["rbacx.dsl.validate"] = mod

    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda *a, **k: fc))
    src = S3PolicySource("s3://b/k", validate_schema=True)
    policy = src.load()
    assert policy == {"rules": []}
    assert fc._last_body is not None and fc._last_body.closed is True
    assert flag["called"] is True


def test_s3_build_client_defaults_without_real_boto3(monkeypatch):
    # Create fake modules to satisfy imports inside _build_client
    fake_boto3 = types.ModuleType("boto3")
    fake_session_mod = types.SimpleNamespace(
        Session=lambda: types.SimpleNamespace(client=lambda *a, **k: object())
    )
    fake_boto3.session = fake_session_mod  # type: ignore[attr-defined]

    class FakeConfig:
        def __init__(self, **kwargs):
            # Keep attrs to prove we built it with desired defaults
            self.kwargs = kwargs

    fake_botocore_config = types.ModuleType("botocore.config")
    fake_botocore_config.Config = FakeConfig  # type: ignore[attr-defined]

    # Inject into sys.modules and call _build_client(None, None, {})
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    monkeypatch.setitem(sys.modules, "botocore.config", fake_botocore_config)

    # If it doesn't raise, we covered the default path; returned object type is opaque
    client = S3PolicySource._build_client(session=None, cfg=None, extra={})
    assert client is not None

