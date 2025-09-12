
# Policy stores & reloading

RBACX supports external policy sources with ETag-based updates.

## Sources

- **File**: `FilePolicySource(path)` — loads local JSON; ETag is computed from content & mtime.
- **HTTP**: `HTTPPolicySource(url)` — uses `If-None-Match` with server-provided `ETag`, returns empty dict on HTTP `304` (not modified).
- **S3**: `S3PolicySource(bucket, key)` — uses `boto3.get_object` and `ETag` header.

Use `PolicyManager` to apply updates to a running `Guard`:

```python
# prepare a minimal policy file for the example
import json, os
if not os.path.exists('policy.json'):
    json.dump({"algorithm":"deny-overrides","rules":[]}, open('policy.json','w'))

from rbacx.core.engine import Guard
from rbacx.store.file_store import FilePolicySource
from rbacx.store.manager import PolicyManager

guard = Guard(policy={})
mgr = PolicyManager(guard, FilePolicySource("policy.json"))
mgr.poll_once()        # initial load
mgr.start_polling(10)  # optional background polling
```

> HTTP ETag / If-None-Match pattern is documented by MDN. AWS S3 exposes `ETag` on `get_object`. For file watching consider `watchdog`. 
