from __future__ import annotations

from typing import Any, Callable, Tuple

from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], Tuple[Subject, Action, Resource, Context]]
