"""No torch/model dependency: test only the warning text."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("apassy_serve", Path(__file__).resolve().parents[2] / "tools/basemodel/serve.py")
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class TemperatureDiagnostic(unittest.TestCase):
    def warning(self, entries):
        return "laya: this checkpoint ships invalid temperatures or values outside [0.5, 5]; using %s. Treat confidence from the affected entries as uncalibrated." % entries

    def test_choice_bucket_does_not_affect_yes_no(self):
        out = serve.temperature_diagnostic(self.warning("choice:11+=0.1 -> 0.5"))
        self.assertIn("choice:11+", out)
        self.assertIn("does not affect the bouncer's yes/no questions (noul:2)", out)

    def test_noul_bucket_and_type_fallback_may_affect_yes_no(self):
        for entries in ["noul:2=0.1 -> 0.5", "temperature[2]=0.1 -> 0.5", "choice:11+=0.1 -> 0.5, noul:2=0.1 -> 0.5"]:
            self.assertIn("may affect the bouncer's yes/no questions", serve.temperature_diagnostic(self.warning(entries)))

    def test_other_warnings_stay_intact(self):
        self.assertEqual(serve.temperature_diagnostic("other warning"), "other warning")


if __name__ == "__main__":
    unittest.main()
