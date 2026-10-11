## 1. Functional Requirements

| ID | Requirement |
|:--|:--|
| FR-01 | The system shall accept a path to a single .log or .txt file, or to a directory, as a command-line argument. |
| FR-02a | The system shall detect email addresses matching the standard format (local-part@domain). |
| FR-02b | The system shall detect phone numbers with 10 digits in total, with an optional country code (e.g. +1 (555) 123-4567). |
| FR-03a | The system shall detect AWS Access Key IDs starting with the prefix AKIA, ASIA, AROA or AIDA, followed by 16 uppercase letters or digits. |
| FR-03b | The system shall detect password or secret assignments where the line contains one of the keywords: password, passwd, pwd, or secret, followed by a colon or equals sign, and a value of at least 4 characters (e.g. password = value, pwd: value, secret="value"). |
| FR-03c | The system shall detect PEM-format private key blocks, from a 'BEGIN PRIVATE KEY' header to its matching 'END PRIVATE KEY' footer, with a maximum of 100 lines in between. |
| FR-03d | The system shall detect MD5, SHA1, and SHA256 hash values based on their fixed hexadecimal length (32, 40, and 64 characters respectively). |
| FR-03e | The system shall detect Base64-like tokens made of two parts of at least 20 letters, digits, hyphens or underscores, separated by a full stop. |
| FR-04 | The system shall produce a Risk Report showing what was found, where (line number), and what type of finding it is. |
| FR-05 | The system shall produce a Redacted Log file where all detected PII and secrets are masked. |
| FR-06 | The system shall reject a missing file with a FileNotFoundException, and a file that is not .log or .txt with an ArgumentException, each with a clear error message. |
| FR-07 | The system shall let the user write the Risk Report to a file using the --out argument. |
| FR-08 | The system shall mask every finding before it is displayed or saved, so only the first 4 and last 4 characters are visible. Values of 8 characters or fewer shall be fully masked. |
| FR-09 | The system shall report a credit card number only if it is 13 to 19 digits long and passes the Luhn checksum. |
| FR-10 | When given a directory, the system shall scan all .log and .txt files in it, including files in nested subdirectories. |
| FR-11 | When scanning a directory, the system shall skip any file or folder excluded by a .gitignore file, and shall not report secrets from them. |
| FR-12 | When scanning a directory, the system shall skip files that are not .log or .txt without raising an error. |

## 2. Non-Functional Requirements

| ID | Requirement | Quality Attribute |
|:--|:--|:--|
| NFR-01 | The system shall process a log file up to 10MB within 5 seconds. | Performance |
| NFR-02 | The system shall detect 100% (10 of 10) of the findings planted in the Secrets.log test file, with the correct pattern name and line number for each. | Reliability |
| NFR-03 | The system shall never send scanned files or findings anywhere externally. | Security |
| NFR-04 | The system shall run as a command-line tool that developers can invoke manually, returning a non-zero exit code when secrets or PII are found, so the scan result can block a git push. | Usability |
| NFR-05 | The detection logic (regex patterns, Luhn validation and masking) shall be kept in separate classes from the command-line entry point and directory scanning, so rules can be updated on their own. | Maintainability |
| NFR-06 | The system shall run on Windows without needing extra paid tools or accounts. | Portability / Compatibility |
| NFR-07 | The system shall not keep or log the contents of scanned files after the run ends, unless the user exports a report. | Security / Compliance |

## Acceptance Criteria for Key Features

| Key Feature | Acceptance Criteria |
|:--|:--|:--|
| Secret and PII detection | AC-01 | Given a test log file of at least 5,000 lines containing 10 planted secrets across different types (email, phone number, AWS key, password/secret assignment using the keywords password, passwd, pwd, or secret, private key block, and hash), the scanner shall detect 100% (10 of 10) of the planted findings, each with the correct type and line number. |
| Credit card checksum | AC-02 | If a number passes checksum check, it should show as a finding, otherwise it shouldn’t show to reduce false positives. |
| Masking | AC-03 | Whenever a finding is shown and saved, only first and last four characters should be visible at most in the save file, the rest is replaced by asterisks, unless it is less than 8 characters long.  |
| User warning before commit | AC-04 | If scanner finds anything, it should give user warning and if it finds nothing, it exits cleanly and the push can be done. |