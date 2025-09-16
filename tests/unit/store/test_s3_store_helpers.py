import pytest

boto3 = pytest.importorskip("boto3")
botocore = pytest.importorskip("botocore")

import json

import pytest

from rbacx.store.s3_store import S3PolicySource, _parse_s3_url


def test_parse_s3_url_ok_and_error():
    loc = _parse_s3_url("s3://bucket/path/to/key.json")
    assert loc.bucket == "bucket" and loc.key == "path/to/key.json"
    with pytest.raises(ValueError):
        _parse_s3_url("http://not-s3/url")


class _Body:
    def __init__(self, data: bytes):
        self._d = data

    def read(self):
        return self._d

    def close(self):
        pass


class _Client:
    class exceptions:
        class NoSuchKey(Exception):
            pass

    def __init__(self, head=None, body=b"{}"):
        self._head = head or {}
        self._body = body

    def head_object(self, **kw):
        return self._head

    def get_object(self, **kw):
        return {"Body": _Body(self._body)}

    def get_object_attributes(self, **kw):
        # Return checksum-related keys from head to emulate AWS response fields
        return self._head


def _mk_source(head_overrides: dict, body_obj: dict = None):
    url = "s3://b/k.json"
    src = S3PolicySource(url, validate_schema=False)
    src._client = _Client(
        head=head_overrides, body=json.dumps(body_obj or {"rules": []}).encode("utf-8")
    )
    return src


@pytest.mark.parametrize(
    "candidates, expected",
    [
        ({"ChecksumSHA256": "aaa"}, ("sha256", "aaa")),
        ({"ChecksumCRC32C": "bbb"}, ("crc32c", "bbb")),
        ({"ChecksumSHA1": "ccc"}, ("sha1", "ccc")),
        ({}, None),
    ],
)
def test_checksum_selection_preference_order(candidates, expected):
    src = _mk_source(candidates, body_obj={})
    got = src._get_checksum()
    assert got == expected


def test_head_etag_stripped_quotes():
    src = _mk_source({"ETag": '"deadbeef"'}, body_obj={})
    assert src._head_etag() == "deadbeef"


def test_load_reads_and_parses_json():
    body = {"policy": {"algorithm": "first", "rules": []}}
    src = _mk_source({}, body_obj=body)
    loaded = src.load()
    assert isinstance(loaded, dict) and "policy" in loaded
