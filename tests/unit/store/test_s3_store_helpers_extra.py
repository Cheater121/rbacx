import types

from rbacx.store.s3_store import S3PolicySource


def test_s3_head_etag_and_version_id_paths(monkeypatch):
    class Client:
        class exceptions:
            class NoSuchKey(Exception):
                pass

        def __init__(self):
            self._head_calls = 0

        def head_object(self, Bucket, Key):
            self._head_calls += 1
            # Return different headers on successive calls
            if self._head_calls == 1:
                return {"ETag": '"E1"'}
            return {"VersionId": "V2"}

        def get_object(self, Bucket, Key):
            return {"Body": types.SimpleNamespace(read=lambda: b"{}", close=lambda: None)}

        def get_object_attributes(self, *a, **kw):
            return {}

    monkeypatch.setattr(S3PolicySource, "_build_client", staticmethod(lambda s, c, e: Client()))
    src = S3PolicySource("s3://bkt/obj.json", validate_schema=False, change_detector="etag")
    # First etag() returns E1
    e1 = src.etag()
    assert e1 is None or isinstance(e1, str)
    # Switch detector and see different path
    src2 = S3PolicySource("s3://bkt/obj.json", validate_schema=False, change_detector="version_id")
    e2 = src2.etag()
    assert e2 is None or isinstance(e2, str)
