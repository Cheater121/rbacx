import sys
import types

import pytest

# Module under test
from rbacx.store.s3_store import S3PolicySource

# --------- Helpers ---------


class FakeSession:
    def __init__(self):
        self.called = None
        self.return_client = object()

    def client(self, name, **kwargs):
        self.called = (name, kwargs)
        return self.return_client


def _must_not_be_called(*args, **kwargs):
    raise AssertionError("boto3 Session must NOT be instantiated when a session is provided")


# --------- _build_client: 81–90, 91 (uses the provided session) ---------


def test_build_client_uses_given_session_and_creates_default_Config(monkeypatch):
    """
    Covers:
      - 81–90: creating a default Config if cfg is None and Config is available
      - 91: sess = session (use the provided session, do NOT create boto3.session.Session)
      - return branch with config (up to and including line 99)
    """
    # Stub boto3 so that creating a session externally is forbidden (if it's called — we fail)
    boto3_mod = types.ModuleType("boto3")
    boto3_mod.session = types.SimpleNamespace(Session=_must_not_be_called)
    boto3_mod.Session = _must_not_be_called
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    # Stub botocore.config with a valid Config
    botocore_pkg = types.ModuleType("botocore")
    botocore_config_mod = types.ModuleType("botocore.config")

    class FakeConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    botocore_config_mod.Config = FakeConfig
    monkeypatch.setitem(sys.modules, "botocore", botocore_pkg)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config_mod)

    fake_sess = FakeSession()
    client = S3PolicySource._build_client(session=fake_sess, cfg=None, extra={"x": 1})

    # Ensure we called the provided session (and did not create a new one)
    assert client is fake_sess.return_client
    assert fake_sess.called is not None
    svc, kwargs = fake_sess.called
    assert svc == "s3"
    # The default Config must be passed
    assert "config" in kwargs and isinstance(kwargs["config"], FakeConfig)
    # Extra kwargs must also be forwarded
    assert kwargs.get("x") == 1


# --------- _build_client: 100 (branch without config) ---------


def test_build_client_without_Config_returns_plain_client(monkeypatch):
    """
    Covers:
      - 100: return sess.client("s3", **(extra or {})) — when Config is unavailable and cfg is None
    """
    # boto3 as before
    boto3_mod = types.ModuleType("boto3")
    boto3_mod.session = types.SimpleNamespace(Session=_must_not_be_called)
    boto3_mod.Session = _must_not_be_called
    monkeypatch.setitem(sys.modules, "boto3", boto3_mod)

    # botocore.config exists but WITHOUT the Config symbol, so that `from ... import Config` raises ImportError
    botocore_pkg = types.ModuleType("botocore")
    botocore_config_mod = types.ModuleType("botocore.config")
    # important: we intentionally do NOT set .Config
    monkeypatch.setitem(sys.modules, "botocore", botocore_pkg)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config_mod)

    fake_sess = FakeSession()
    client = S3PolicySource._build_client(session=fake_sess, cfg=None, extra={"y": 2})

    assert client is fake_sess.return_client
    svc, kwargs = fake_sess.called
    assert svc == "s3"
    # There must be no config
    assert "config" not in kwargs
    assert kwargs.get("y") == 2


# --------- _get_checksum: 128–129 (prefer the requested algorithm) ---------


class StubClientChecksum:
    def get_object_attributes(self, **kwargs):
        # Return only CRC32C (enough to check prefer_checksum)
        return {
            "ChecksumCRC32C": "crc32c_val_base64",
            "ChecksumSHA256": None,
            "ChecksumSHA1": None,
            "ChecksumCRC32": None,
            "ChecksumCRC64NVME": None,
        }


def test_get_checksum_prefers_requested_algo(monkeypatch):
    """
    Covers lines 128–129:
      - when prefer_checksum is set and the corresponding value is present — return that one.
    """
    src = S3PolicySource(
        url="s3://b/k",
        client=StubClientChecksum(),
        change_detector="checksum",
        prefer_checksum="crc32c",
    )
    algo, value = src._get_checksum()
    assert algo == "crc32c"
    assert value == "crc32c_val_base64"


# --------- _get_object_bytes: 183–189 (ETag with and without quotes) ---------


class _Body:
    def __init__(self, payload: bytes = b"{}"):
        self._p = payload

    def read(self):
        return self._p

    def close(self):
        pass


class StubClientGetObject:
    def __init__(self, etag):
        self._etag = etag

    def get_object(self, **kwargs):
        return {"ETag": self._etag, "Body": _Body(b'{"ok": true}')}


@pytest.mark.parametrize(
    "etag_in, etag_expected",
    [
        ('"abc123"', "abc123"),  # with quotes
        ("xyz789", "xyz789"),  # without quotes
    ],
)
def test_get_object_bytes_updates_cached_etag(etag_in, etag_expected):
    """
    Covers 183–189: stripping quotes and the elif branch for a string without quotes.
    """
    src = S3PolicySource(url="s3://b/k", client=StubClientGetObject(etag_in))
    data = src._get_object_bytes()
    assert data == b'{"ok": true}'
    assert src._etag == etag_expected


# --------- load(): 202 and 204 (parse_policy_bytes + validate_schema branch) ---------


def test_load_parses_and_validates(monkeypatch):
    """
    Covers:
      - 202: policy = parse_policy_bytes(...)
      - 204: if self.validate_schema: (enter and call validate_policy)
    """
    # Patch parse_policy_bytes inside the module
    import rbacx.store.s3_store as s3mod

    called = {}

    def fake_parse_policy_bytes(raw: bytes, filename: str):
        called["parsed"] = (raw, filename)
        return {"parsed": True, "fname": filename}

    monkeypatch.setattr(s3mod, "parse_policy_bytes", fake_parse_policy_bytes, raising=True)

    # Stub module rbacx.dsl.validate so the import succeeds and the function is called
    validate_mod = types.ModuleType("rbacx.dsl.validate")

    def validate_policy(policy):
        called["validated"] = policy

    validate_mod.validate_policy = validate_policy
    monkeypatch.setitem(sys.modules, "rbacx.dsl.validate", validate_mod)

    # Avoid network/client — patch _get_object_bytes
    monkeypatch.setattr(
        S3PolicySource,
        "_get_object_bytes",
        lambda self: b'{"some": "json"}',
        raising=True,
    )

    src = S3PolicySource(url="s3://b/key.json", client=object(), validate_schema=True)
    result = src.load()

    # Assertions: parsed and validated
    assert called.get("parsed") == (b'{"some": "json"}', "key.json")
    assert called.get("validated") == {"parsed": True, "fname": "key.json"}
    assert result == {"parsed": True, "fname": "key.json"}


# ---- 127–129: defensive default in etag() (non-standard change_detector) ----


def test_etag_defensive_default_hits_lines_127_129(monkeypatch):
    """
    Covers the defensive default path in etag() when change_detector is unrecognized.
    We stub _head_etag to return a marker value, then expect etag() to format it as 'etag:<value>'.
    """
    # Do not touch the network: patch _head_etag to return a marker
    monkeypatch.setattr(S3PolicySource, "_head_etag", lambda self: "EEE", raising=True)

    # Pass an unrecognized change_detector -> we should go through the defensive default
    src = S3PolicySource(
        url="s3://b/k", client=object(), change_detector="__weird__", validate_schema=False
    )
    assert src.etag() == "etag:EEE"  # lines 127–129 executed


# A tiny client stub you can parametrize with checksum fields
class _ClientChecksums:
    def __init__(self, **vals):
        self._vals = {
            "ChecksumSHA256": None,
            "ChecksumCRC32C": None,
            "ChecksumSHA1": None,
            "ChecksumCRC32": None,
            "ChecksumCRC64NVME": None,
            **vals,
        }

    def get_object_attributes(self, **kwargs):
        # Ensure we're actually requesting checksum attributes
        assert kwargs.get("ObjectAttributes") == ["Checksum"]
        return dict(self._vals)


# 1) prefer_checksum is present AND available -> early return from the 'if' block (183–186)
def test_get_checksum_prefer_found_returns_early():
    cli = _ClientChecksums(ChecksumCRC32C="crc32c_val")
    src = S3PolicySource(
        url="s3://b/k",
        client=cli,
        change_detector="checksum",
        prefer_checksum="crc32c",
        validate_schema=False,
    )
    assert src._get_checksum() == ("crc32c", "crc32c_val")


# 2) prefer_checksum is present BUT missing -> enter the for-loop and pick the first available by order (hits 189)
def test_get_checksum_prefer_missing_falls_to_loop():
    cli = _ClientChecksums(ChecksumSHA1="sha1_val")
    src = S3PolicySource(
        url="s3://b/k",
        client=cli,
        change_detector="checksum",
        prefer_checksum="sha256",  # requested, but not present
        validate_schema=False,
    )
    assert src._get_checksum() == ("sha1", "sha1_val")


# 3) prefer_checksum=None -> skip the 'if', go straight to the loop and pick the first available ('sha256')
def test_get_checksum_no_prefer_uses_first_available_in_loop():
    cli = _ClientChecksums(ChecksumSHA256="sha256_val")
    src = S3PolicySource(
        url="s3://b/k",
        client=cli,
        change_detector="checksum",
        prefer_checksum=None,
        validate_schema=False,
    )
    assert src._get_checksum() == ("sha256", "sha256_val")


# 4) Loop exhausts without finding any value -> return None after the loop
def test_get_checksum_loop_exhausted_returns_none():
    cli = _ClientChecksums()  # everything None
    src = S3PolicySource(
        url="s3://b/k",
        client=cli,
        change_detector="checksum",
        prefer_checksum=None,
        validate_schema=False,
    )
    assert src._get_checksum() is None
