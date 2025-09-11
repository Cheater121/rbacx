# Auto-patch for litestar_guard API change: expose require_check alias
import sys, types

# Provide minimal litestar shim so rbacx.adapters.litestar_guard can import
if 'litestar.connection' not in sys.modules:
    conn_mod = types.ModuleType('litestar.connection')
    class ASGIConnection:  # minimal placeholder
        pass
    conn_mod.ASGIConnection = ASGIConnection
    sys.modules['litestar.connection'] = conn_mod

if 'litestar.exceptions' not in sys.modules:
    exc_mod = types.ModuleType('litestar.exceptions')
    class PermissionDeniedException(Exception):
        pass
    exc_mod.PermissionDeniedException = PermissionDeniedException
    sys.modules['litestar.exceptions'] = exc_mod

try:
    import rbacx.adapters.litestar_guard as lg
    if not hasattr(lg, 'require_check') and hasattr(lg, 'require'):
        setattr(lg, 'require_check', getattr(lg, 'require'))
except Exception:
    # If import still fails for any reason, leave it; individual tests may skip.
    pass