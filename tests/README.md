Regression tests for iocextract
=======

Test data should be formed in pairs of json and txt files in a form:
<br/>%family%_%config_id%.json
<br/>%family%_%config_id%.txt

**Sample invocation of regression tests:**

When in iocextract directory:
<br/>
```python
python3 -m tests.test_parse_regression
```
**To generate test data:**

- download recent configs from MWDB:
<br/>
```python
python3 -m tests.download_test_data {mwdb_user} {mwdb_pass}
```

- download particular config from MWDB by giving config_id:
<br/>
```python
python3 -m tests.download_test_data {mwdb_user} {mwdb_pass} {config_id}
```
- generate .txt files from all downloaded .json files
```python
python3 -m tests.parse_test_data
```
- generate .txt file from particular .json based on family and config_id
```python
python3 -m tests.parse_test_data {family} {config_id}
```

\* in {} your own values should be given
