
from rbacx.core.engine import Guard
def build_guard() -> Guard:
    return Guard({"rules":[{"id":"p","effect":"permit","actions":["read"],"resource":{"type":"doc"}}]})
