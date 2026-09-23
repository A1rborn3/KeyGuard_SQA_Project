# Acceptance Criteria — All Requirements

## Functional Requirements

| ID | Requirement | Acceptance Criteria |
|:--|:--|:--|
| FR-01 | The system shall accept a log file path and read its contents for scanning. | Given a valid file path, when the scan is run, then the system reads and processes every line without error. |
| FR-02a | The system shall detect email addresses matching standard email format. | Given a file containing a known valid email address, when the file is scanned, then it is reported as a finding with the correct line number. |
| FR-02b | The system shall detect phone numbers in common formats. | Given a file containing a known valid phone number, when the file is scanned, then it is reported as a finding with the correct line number, without overlapping with a credit card number match on the same line. |
| FR-03a | The system shall detect AWS Access Key IDs, including access keys, temporary/STS keys, and role keys. | Given a file containing a sample key with an AKIA, ASIA, AROA, or AIDA prefix, when the file is scanned, then it is reported as an "AWS Access Key ID" finding. |
| FR-03b | The system shall detect secret assignments using the keywords password, passwd, pwd, or secret, followed by a colon or equals sign and a value of at least 4 characters. | Given a line such as `password = value` or `pwd: value`, when the file is scanned, then it is reported as a "Password assignment" finding containing only the value, not the keyword. |
| FR-03c | The system shall detect PEM-format private key blocks, from a "-----BEGIN PRIVATE KEY-----" header to its matching "-----END PRIVATE KEY-----" footer. | Given a file containing a private key block with both header and footer present, when the file is scanned, then the entire block is reported as a single "Private Key Block" finding starting at the header's line number. |
| FR-03d | The system shall detect MD5, SHA1, and SHA256 hash values based on their fixed hexadecimal length. | Given a file containing a 32, 40, or 64 character hexadecimal string, when the file is scanned, then it is reported as an "MD5 Hash", "SHA1 Hash", or "SHA256 Hash" finding respectively. |
| FR-04 | The system shall validate suspected credit card numbers using the Luhn algorithm before reporting them as a finding. | Given a 13–19 digit number sequence that passes the Luhn checksum, when the file is scanned, then it is reported as a "Credit Card (possible)" finding; given a sequence that fails the checksum, then it is not reported. |
| FR-05 | The system shall mask every detected finding before displaying or saving it. | Given any finding longer than 8 characters, when it is displayed or saved, then only the first 4 and last 4 characters are visible, with the rest replaced by asterisks. |
| FR-06 | The system shall report each finding's line number, pattern name, and masked value to the console as it scans. | Given a scan is run, when a finding is detected, then its line number, pattern name, and masked value are printed to the console at the time of detection. |
| FR-07 | The system shall allow the user to export the Risk Report and Redacted Log file. | Given the `--out` argument is supplied, when the scan completes, then a report file is created containing the line number, pattern name, and masked value of every finding. |
| FR-08 | The system shall reject files that are not in an accepted log format, and reject files that do not exist, with clear error messages. | Given a file path that does not exist, when a scan is attempted, then a `FileNotFoundException` is thrown with a clear message; given a file that is not `.txt` or `.log`, when a scan is attempted, then an `ArgumentException` is thrown stating the file type is invalid. |

## Non-Functional Requirements

| ID | Requirement | Acceptance Criteria |
|:--|:--|:--|
| NFR-01 | The system shall process a log file of up to 10MB within 5 seconds. | Given a 10MB test log file, when a scan is run and timed, then the scan completes in 5 seconds or less. |
| NFR-02 | The system shall reduce false positives for number-based findings using checksum validation. | Given the `Secrets.log` test file containing both Luhn-valid and Luhn-invalid digit sequences, when the file is scanned, then only the Luhn-valid sequence is reported as a credit card finding. |
| NFR-03 | The system shall never send scanned file contents anywhere externally. | Given a scan is run, when network activity is monitored during the scan, then no outbound network requests are made. |
| NFR-04 | The system shall run as a command-line tool that developers can invoke manually or via a pre-commit hook, returning a non-zero exit code when secrets or PII are found. | Given a scan finds one or more findings, when the tool finishes, then it returns a non-zero exit code; given no findings, then it returns a zero exit code. |
| NFR-05 | The detection logic shall be kept separate from the interface code, so rules can be updated on their own. | Given a new pattern needs to be added, when `SecretsScanner.Patterns` is updated, then no changes are required to `Program.cs` (the CLI entry point) for the new pattern to take effect. |
| NFR-06 | The system shall run without needing extra paid tools or external accounts. | Given a machine with only .NET installed, when the tool is built and run, then it functions correctly with no additional paid software or account sign-up required. |
| NFR-07 | The system shall not keep or log scanned file contents after the session ends, unless the user exports them. | Given a scan is run without the `--out` argument, when the process exits, then no file containing the scanned content or findings is left on disk. |