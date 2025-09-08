
# Django REST Framework example

A minimal runnable project is included in `examples/drf_demo`.

```bash
pip install -e .[adapters-drf]
python examples/drf_demo/manage.py runserver 127.0.0.1:8001
curl -i http://127.0.0.1:8001/docs
```

It uses `rbacx.adapters.drf.make_permission` to build a permission class from a `Guard`. See DRF docs on custom permissions and `BasePermission.has_permission`. 
