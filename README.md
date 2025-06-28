# Secret-Hunter

Secret-Hunter is a single-file Python tool that finds hard-coded credentials in source trees.  
It looks for the most common high-value secrets:

| Kind of secret | Pattern detected |
| -------------- | ---------------- |
| AWS access key | `AKIA` followed by sixteen uppercase letters or digits |
| Generic API key | Alphanumeric strings of length thirty-two or more |
| Private key header | Lines that begin with `-----BEGIN <TYPE> PRIVATE KEY-----` |
| Password assignment | Code lines that assign to variables named `password` |

The script prints a one-line report for every match and exits with **“No secrets found ✓”** when the scan is clean.

---

## Requirements

* Python 3.7 or newer  
* No external packages

---

## Running the scanner

```shell
python secret_hunter.py <path_to_scan>
# Omit <path_to_scan> to scan the current directory
