Regression tests for iocextract

configs directory - directory where json files should be stored in form of
%family%_%config_id%.json
expected directory - directory where expected result txt files should be stored in form of
%family%_%config_id%.txt

Sample invocation of regression tests:

When in iocextract directory:
python3 -m tests.test_parse_regression

To generate test data:

- from recent configs from MWDB
python3 -m tests.generate_test_data {mwdb_user} {mwdb_pass}

- from particular config from MWDB by giving config_id
python3 -m tests.generate_test_data {mwdb_user} {mwdb_pass} {config_id}

* in {} your own values should be given
