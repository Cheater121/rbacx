
import sys, types, json
from rbacx.storage.s3 import S3PolicySource

class _Body:
    def __init__(self, data): self._d=data
    def read(self): return self._d.encode("utf-8")

class FakeClient:
    def __init__(self): self._etag="xyz"
    def head_object(self, Bucket, Key):
        return {"ETag": '"%s"'%self._etag}
    def get_object(self, Bucket, Key):
        return {"Body": _Body('{"rules":[]}')}

class Session:
    def __init__(self, profile_name=None): ...
    def client(self, name, region_name=None): return FakeClient()

sys.modules["boto3"]=types.SimpleNamespace(Session=Session)

def test_s3_policy_source_etag_and_load(monkeypatch):
    src = S3PolicySource(bucket="b", key="k", region_name="r")
    assert src.etag()=="xyz"
    assert src.load()["rules"]==[]
