from typing import cast

from .local import ComputedUserset, This, TupleToUserset, UsersetExpr


def standard_userset(
    parent_rel: str | None = None, with_group_grants: bool = True
) -> dict[str, UsersetExpr]:
    rules: dict[str, list[UsersetExpr]] = {
        "viewer": [This(), ComputedUserset("editor")],
        "editor": [This(), ComputedUserset("owner")],
        "owner": [This()],
    }
    if parent_rel:
        for rel in ("viewer", "editor", "owner"):
            rules[rel].append(TupleToUserset(parent_rel, rel))
    if with_group_grants:
        rules["viewer"].append(TupleToUserset("granted", "member"))
    return cast(dict[str, UsersetExpr], rules)
