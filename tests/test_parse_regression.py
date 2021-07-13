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

            split_filename = config_file.split(".")
            print(split_filename[0])

            iocs = parse(config["type"], config)

            expected_file_txt = split_filename[0] + ".txt"

            with open(testdir + expected_file_txt, "rb") as exp:
                expected_data = exp.read().decode("utf-8")

            if expected_data != iocs.prettyprint() + "\n":
                print("EXPECTED")
                print(expected_data)
                print("GOT")
                print(iocs.prettyprint())
                self.assertTrue(False)


if __name__ == "__main__":
    unittest.main()
