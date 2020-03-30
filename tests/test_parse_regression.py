import unittest
import json
from src.api import parse
import os


class TestParseRegression(unittest.TestCase):
    def test_regression(self):
        current_path = os.path.abspath(os.path.dirname(__file__))
        testdir = current_path + "/testdata/"

        config_files = [f for f in os.listdir(testdir) if f.endswith(".json")]

        for config_file in config_files:
            with open(testdir + config_file) as cfg:
                config_raw = cfg.read()
                config = json.loads(config_raw)

            iocs = parse(config["type"], config)

            split_filename = config_file.split(".")
            expected_file_txt = split_filename[0] + ".txt"

            with open(testdir + expected_file_txt, "rb") as exp:
                expected_data = exp.read().decode("utf-8")

            print(split_filename[0])

            self.assertEqual(expected_data, iocs.prettyprint() + "\n")


if __name__ == "__main__":
    unittest.main()
