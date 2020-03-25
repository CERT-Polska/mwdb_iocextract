import filecmp
import unittest
from mwdblib import Malwarecage
import json
from src.api import parse
import os


class TestAnalysisRegressions(unittest.TestCase):
    def test_regressions(self):
        mwdb = Malwarecage()
        mwdb.login("dsk", "12loop12")

        config_id = "329c41c8070899b8bf840c2d181e7112a3d221449dcad572f7e98b35b29a8730"
        current_path = os.path.abspath(os.path.dirname(__file__))
        testdir = current_path+"/testdata/"
        mwdb_config = mwdb.query_config(config_id)
        print(mwdb_config.cfg)
        print("Type: "+str(type(mwdb_config.cfg)))

        file_name_json = mwdb_config.family + config_id + ".json"

        generate_config_json_file(testdir, file_name_json, mwdb_config)

        with open(testdir+file_name_json) as cfg:
            config_raw = cfg.read()
            config = json.loads(config_raw)

        iocs = parse(config["type"], config)

        file_name_txt = mwdb_config.family + config_id + ".txt"
        with open(testdir+file_name_txt, 'w') as fp:
            fp.write(iocs.prettyprint())

        expected_file_name = mwdb_config.family + config_id + "expected.txt"
        generate_expected_file(testdir, expected_file_name, iocs)

        #Assert result of pretty_print is equal to expected
        self.assertTrue(filecmp.cmp(testdir+file_name_txt, testdir + expected_file_name, shallow=True))


def generate_config_json_file(testdir, file_name_json, mwdb_config):
    with open(testdir + file_name_json, 'w') as fp:
        json.dump(mwdb_config.config_dict, fp)


def generate_expected_file(testdir, expected_file_name, iocs):
    with open(testdir + expected_file_name, 'w') as fp:
        fp.write(iocs.prettyprint())


if __name__ == '__main__':
    unittest.main()
