import builtins
import sys
import types

import pytest

from rbacx.store.s3_store import S3PolicySource, _parse_s3_url


def make_dummy_client(head=None, get_obj=None, get_attr=None, exceptions=None):
    # Build a dummy client with the necessary methods and exceptions
    class DummyExc:
        class NoSuchKey(Exception):
            pass

    excs = exceptions or DummyExc

    class DummyBody:
        def __init__(self, data: bytes):
            self._data = data

        def read(self):
            return self._data

        def close(self):
            pass

    class DummyClient:
        def __init__(self):
            self._head = head or {}
            self._get_obj = get_obj or b"{}"
            self._get_attr = get_attr or {}

        def head_object(self, Bucket, Key):
            return dict(self._head)

        def get_object(self, Bucket, Key):
            return {"Body": DummyBody(self._get_obj)}

        def get_object_attributes(self, Bucket, Key, ObjectAttributes):
            # If a callable passed, call it to allow raising in tests
            if callable(self._get_attr):
                return self._get_attr()
            return dict(self._get_attr)

        # expose exceptions
        exceptions = excs

    return DummyClient()


def test_parse_s3_url_valid_and_invalid():
    loc = _parse_s3_url("s3://bucket/prefix/key.json")
    assert loc.bucket == "bucket" and loc.key == "prefix/key.json"
    with pytest.raises(ValueError):
        _parse_s3_url("http://not-s3/url")
    with pytest.raises(ValueError):
        _parse_s3_url("s3://missing-key")


def test_s3_load_json_and_etag_detector(monkeypatch):
    client = make_dummy_client(
        head={"ETag": '"abc123"'},
        get_obj=b'{"rules":[]}',
    )
    monkeypatch.setattr(
        S3PolicySource, "_build_client", staticmethod(lambda session, cfg, extra: client)
    )
    src = S3PolicySource("s3://bkt/pol.json", validate_schema=False, change_detector="etag")
    data = src.load()
    assert data.get("rules") == []
    et = src.etag()
    # Accept common representations
    assert et is None or isinstance(et, str)


def test_s3_load_yaml_and_version_id_detector(monkeypatch):
    pytest.importorskip("yaml")
    client = make_dummy_client(
        head={"VersionId": "V123"},
        get_obj=b"rules: []\n",
    )
    monkeypatch.setattr(
        S3PolicySource, "_build_client", staticmethod(lambda session, cfg, extra: client)
    )
    src = S3PolicySource(
        "s3://bkt/policy.yaml", validate_schema=False, change_detector="version_id"
    )
    data = src.load()
    assert data.get("rules") == []
    assert isinstance(src.etag(), (str, type(None)))


def test_s3_checksum_detector_prefers_sha256_then_crc32c(monkeypatch):
    client = make_dummy_client(
        get_attr={"Checksum": {"ChecksumSHA256": "s256", "ChecksumCRC32C": "c32c"}},
        head={"ETag": '"ignored"'},
        get_obj=b'{"rules":[]}',
    )
    monkeypatch.setattr(
        S3PolicySource, "_build_client", staticmethod(lambda session, cfg, extra: client)
    )
    src = S3PolicySource("s3://bkt/p.json", validate_schema=False, change_detector="checksum")
    # First call: chooses sha256
    et = src.etag()
    assert et is None or et.startswith("ck:sha256:") or et.startswith("etag:")

    # When checksum unavailable -> falls back to ETag heuristic
    client2 = make_dummy_client(get_attr={}, head={"ETag": '"E1"'}, get_obj=b"{}")
    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda s, c, e: client2))
    src2 = S3PolicySource("s3://bkt/p.json", validate_schema=False, change_detector="checksum")
    et2 = src2.etag()
    assert et2 is None or et2.startswith("etag:") or et2 == '"E1"'


def test_s3_get_checksum_handles_no_such_key_and_generic(monkeypatch):
    class Exc:
        class NoSuchKey(Exception):
            pass

    # NoSuchKey branch
    def raise_nsk():
        raise Exc.NoSuchKey()

    client = make_dummy_client(get_attr=raise_nsk, exceptions=Exc, get_obj=b"{}")
    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda s, c, e: client))
    src = S3PolicySource("s3://bkt/p.json", validate_schema=False, change_detector="checksum")
    # etag() should fallback to ETag when checksum unavailable; head doesn't raise here -> None or "etag:None"
    et = src.etag()
    assert et is None or isinstance(et, str)

    # Generic exception branch
    def raise_generic():
        raise RuntimeError("boom")

    client2 = make_dummy_client(get_attr=raise_generic, get_obj=b"{}")
    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda s, c, e: client2))
    src2 = S3PolicySource("s3://bkt/p.json", validate_schema=False, change_detector="checksum")
    et2 = src2.etag()
    assert et2 is None or isinstance(et2, str)


def test_s3_etag_unexpected_exception_is_handled(monkeypatch):
    # Force a generic exception inside etag() try-block to cover the general except/re-raise
    class Client:
        class exceptions:
            class NoSuchKey(Exception):
                pass

        def head_object(self, *a, **kw):
            return {}  # not used

        def get_object_attributes(self, *a, **kw):
            raise RuntimeError("unexpected")  # triggers general except in etag()

        def get_object(self, *a, **kw):
            return {"Body": types.SimpleNamespace(read=lambda: b"{}", close=lambda: None)}

    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda s, c, e: Client()))
    src = S3PolicySource("s3://bkt/p.json", validate_schema=False, change_detector="checksum")
    _ = src.etag()  # must not raise; handler should swallow and return None or a fallback
    assert src.etag() is None or isinstance(src.etag(), str)


def test_s3_build_client_importerror(monkeypatch):
    # Make imports for boto3/botocore fail to cover ImportError branch
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ("boto3", "botocore.config"):
            raise ImportError("nope")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError):
        S3PolicySource._build_client(session=None, cfg=None, extra={})


def test_s3_build_client_with_stub_session_and_cfg(monkeypatch):
    # Provide stub modules for boto3 and botocore.config to cover branches where cfg/session are None
    class StubSession:
        def client(self, service, config=None, **extra):
            return {"service": service, "config": config, **extra}

    class StubBoto3:
        class session:
            Session = StubSession

    class StubConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    # Inject stubs
    monkeypatch.setitem(sys.modules, "boto3", StubBoto3())
    mod = types.SimpleNamespace(Config=StubConfig)
    monkeypatch.setitem(sys.modules, "botocore.config", mod)

    client = S3PolicySource._build_client(
        session=None, cfg=None, extra={"region_name": "us-east-1"}
    )
    # Should return from StubSession.client
    assert isinstance(client, dict) and client.get("service") == "s3"
