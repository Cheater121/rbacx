See README for quickstart; includes policy example and HotReloader.


## CLI
```bash
pip install rbacx
rbacx validate --policy examples/fastapi_demo/policy.json
rbacx eval --policy examples/fastapi_demo/policy.json --subject u1 --action read --resource-type article --context '{"mfa": true}'
```
