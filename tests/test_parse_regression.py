import filecmp
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

            result_file_txt = "test_result.txt"
            with open(testdir + result_file_txt, "w") as fp:
                fp.write(iocs.prettyprint() + "\n")

            split_filename = config_file.split(".")
            expected_file_txt = split_filename[0] + ".txt"

            print(split_filename[0])
            self.assertTrue(
                filecmp.cmp(
                    testdir + result_file_txt,
                    testdir + expected_file_txt,
                    shallow=True,
                )
            )


if __name__ == "__main__":
    unittest.main()
