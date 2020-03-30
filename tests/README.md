Regression tests for iocextract
=======

Test data should be formed in pairs of json and txt files in a form:

%family%_%config_id%.json

%family%_%config_id%.txt

**Sample invocation of regression tests:**

When in iocextract directory:

```
python3 -m tests.test_parse_regression
```

**To generate test data:**

- download recent configs from MWDB:

```
python3 -m tests.download_test_data {mwdb_user} {mwdb_pass}
```

- download particular config from MWDB by giving config_id:

```
python3 -m tests.download_test_data {mwdb_user} {mwdb_pass} {config_id}
```

- generate .txt files from all downloaded .json files

```
python3 -m tests.parse_test_data
```

- generate .txt file from particular .json based on family and config_id

```
python3 -m tests.parse_test_data {family} {config_id}
```

\* in {} your own values should be given
