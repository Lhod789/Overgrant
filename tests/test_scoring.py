import unittest

from overgrant.catalogue import Scope
from overgrant.findings import Tier
from overgrant.risk import Breadth, Mutability, Sensitivity
from overgrant.scoring import RULES, score


def make_scope(**overrides):
    fields = {
        "id": "test:scope",
        "short": "Test scope",
        "grants": "Does something for a test",
        "breadth": Breadth.SELF,
        "mutability": Mutability.READ,
        "sensitivity": Sensitivity.NONE,
        "data_classes": [],
        "endpoints": [],
        "supersedes": [],
        "admin_consent": False,
        "source": "https://example.com/test",
        "notes": "",
    }
    fields.update(overrides)
    return Scope(**fields)


class TestRulePrecedence(unittest.TestCase):
    def assertScores(self, scope, rule_id, tier):
        finding = score(scope)
        self.assertEqual(finding.rule, rule_id)
        self.assertEqual(finding.tier, tier)

    def test_r1_credentials(self):
        self.assertScores(
            make_scope(sensitivity=Sensitivity.CREDENTIALS),
            "R1-credentials",
            Tier.CRITICAL,
        )

    def test_r2_org_admin(self):
        self.assertScores(
            make_scope(breadth=Breadth.ORG_ADMIN),
            "R2-org-admin",
            Tier.CRITICAL,
        )

    def test_r3_admin_at_scale(self):
        self.assertScores(
            make_scope(mutability=Mutability.ADMIN, breadth=Breadth.WORKSPACE),
            "R3-admin-at-scale",
            Tier.HIGH,
        )

    def test_r4_tenant_wide_content(self):
        self.assertScores(
            make_scope(
                sensitivity=Sensitivity.CONTENT,
                breadth=Breadth.WORKSPACE,
                data_classes=["messages"],
            ),
            "R4-tenant-wide-content",
            Tier.HIGH,
        )

    def test_r5_destructive(self):
        self.assertScores(
            make_scope(mutability=Mutability.DELETE, breadth=Breadth.RESOURCE),
            "R5-destructive",
            Tier.HIGH,
        )

    def test_r6_private_correspondence(self):
        self.assertScores(
            make_scope(
                sensitivity=Sensitivity.CONTENT,
                breadth=Breadth.RESOURCE,
                data_classes=["direct_messages"],
            ),
            "R6-private-correspondence",
            Tier.HIGH,
        )

    def test_r7_content(self):
        self.assertScores(
            make_scope(
                sensitivity=Sensitivity.CONTENT,
                breadth=Breadth.RESOURCE,
                data_classes=["files"],
            ),
            "R7-content",
            Tier.MEDIUM,
        )

    def test_r8_tenant_wide_write(self):
        self.assertScores(
            make_scope(mutability=Mutability.WRITE, breadth=Breadth.WORKSPACE),
            "R8-tenant-wide-write",
            Tier.MEDIUM,
        )

    def test_r9_directory_enumeration(self):
        self.assertScores(
            make_scope(
                sensitivity=Sensitivity.METADATA,
                breadth=Breadth.WORKSPACE,
                data_classes=["profiles"],
            ),
            "R9-directory-enumeration",
            Tier.MEDIUM,
        )

    def test_r10_default(self):
        self.assertScores(make_scope(), "R10-default", Tier.LOW)


class TestRuleOrdering(unittest.TestCase):
    def test_tiers_never_ascend(self):
        for above, below in zip(RULES, RULES[1:]):
            self.assertLessEqual(
                below.tier,
                above.tier,
                f"{below.id} (tier {below.tier.name}) sits below "
                f"{above.id} (tier {above.tier.name})",
            )


if __name__ == "__main__":
    unittest.main()
