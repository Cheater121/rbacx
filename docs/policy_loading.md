# Policy loading & hot reload

RBACX supports external policy sources and a lightweight polling manager.

## Sources
- **File**: `rbacx.storage.FilePolicySource` — loads local JSON; ETag computed from content.
- **HTTP**: `rbacx.store.http_store.HTTPPolicySource` (if available) — conditional GET via ETag.
- **S3**: `rbacx.store.s3_store.S3PolicySource` (if available) — uses the object's ETag.

## Applying updates
```python
from rbacx.core.engine import Guard
from rbacx.storage import FilePolicySource
from rbacx.store.manager import PolicyManager

guard = Guard(policy={})
mgr = PolicyManager(guard, FilePolicySource("policy.json"))
mgr.poll_once()
mgr.start_polling(interval_s=10)
```
