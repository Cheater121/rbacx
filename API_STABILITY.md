# API Stability Guarantees

The following **public imports** from `rbacx` are considered stable starting from **1.0.0**.

```python
from rbacx import Guard
from rbacx import Subject
from rbacx import Action
from rbacx import Resource
from rbacx import Context
from rbacx import Decision
from rbacx import HotReloader
from rbacx import load_policy
from rbacx import core
from rbacx import adapters
from rbacx import storage
from rbacx import obligations
from rbacx import __version__
```

**We guarantee:**
- The names and import paths above remain unchanged across all `1.x` releases.
- If we ever need to move/rename anything, it will go through deprecation, with backwards compatibility kept for at least **two minor releases or six months** (whichever is later).

> Subpackages (`rbacx.core`, `rbacx.policy`, `rbacx.adapters`, etc.) may evolve faster. Only the **root imports** listed above are covered by this compatibility promise.
