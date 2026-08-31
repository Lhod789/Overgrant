import unittest
from overgrant.risk import Breadth, Mutability, Sensitivity


class TestSeverityScales(unittest.TestCase):
    def test_breadth_ascends(self):
        self.assertTrue(
            Breadth.SELF < Breadth.RESOURCE < Breadth.WORKSPACE < Breadth.ORG_ADMIN
        )

    def test_mutability_ascends(self):
        self.assertTrue(
            Mutability.READ < Mutability.WRITE < Mutability.DELETE < Mutability.ADMIN
        )

    def test_sensitivity_ascends(self):
        self.assertTrue(
            Sensitivity.NONE
            < Sensitivity.METADATA
            < Sensitivity.CONTENT
            < Sensitivity.CREDENTIALS
        )


if __name__ == "__main__":
    unittest.main()
