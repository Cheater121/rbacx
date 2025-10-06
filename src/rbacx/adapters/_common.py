from typing import Any, Callable

from ..core.model import Action, Context, Resource, Subject

EnvBuilder = Callable[[Any], tuple[Subject, Action, Resource, Context]]
