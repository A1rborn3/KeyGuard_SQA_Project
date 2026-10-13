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
| FR-05 | The system shall never display or save an unmasked finding in the console output or the report file. |
| FR-06 | The system shall reject a missing file with a FileNotFoundException, and a file that is not .log or .txt with an ArgumentException, each with a clear error message. |
| FR-07 | The system shall write a report file when --out is given. The report has a header (scanned path, timestamp, finding count) and one line per finding with the line number, pattern name and masked value, plus the file path when a directory is scanned. |
| FR-08 | The system shall mask every finding before it is displayed or saved, so only the first 4 and last 4 characters are visible. Values of 8 characters or fewer shall be fully masked. |
| FR-09 | The system shall report a credit card number only if it is 13 to 19 digits long and passes the Luhn checksum. |
| FR-10 | When given a directory, the system shall scan all .log and .txt files in it, including files in nested subdirectories. |
| FR-11 | When scanning a directory, the system shall skip files and folders excluded by the .gitignore in the root of that directory. Supported patterns are comments, * and ? wildcards, ** , trailing slash folder patterns and ! negation. Nested .gitignore files are not read. If there is no .gitignore, all supported files are scanned. |
| FR-12 | When scanning a directory, the system shall skip files that are not .log or .txt, print a message for each skipped file, and not return them in the results. |
| FR-13 | If a file cannot be read during a directory scan, the system shall print an error message for that file and continue with the next file. |

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