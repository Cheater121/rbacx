# Extra format-detection tests for PolicyLoader.
# Skip YAML-specific branches if PyYAML is not installed (CI scenario).
# Comments in English by project rule.
import pytest

yaml = pytest.importorskip("yaml", exc_type=ImportError, reason="PyYAML required for YAML paths")

from importlib import reload

import rbacx.policy.loader as pl


def test_parse_policy_text_uses_filename_extension_when_no_content_type():
    reload(pl)
    # No content-type; extension says .yaml -> YAML parser path (requires PyYAML)
    content = "rules:\n  - id: R1\n    effect: permit"
    policy = pl.parse_policy_text(content, filename="policy.yaml", content_type=None)
    assert isinstance(policy, dict)
    assert policy.get("rules")
