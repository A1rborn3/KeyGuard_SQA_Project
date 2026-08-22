## 1. Functional Requirements

| ID | Requirement |

| FR-01 | The system shall let a user upload a .log or .txt file through the GUI. |
| FR-02 | The system shall scan the uploaded file for PII (like emails and phone numbers) using regex. |
| FR-03a | The system shall detect AWS Access Key IDs matching the standard AKIA prefix format.  |
| FR-03b | The system shall detect password or secret assignments in the form ‘password = value’, ‘pwd: value’, or similar. |
| FR-03c | The system shall detect PEM-format private key blocks, from a ‘BEGIN PRIVATE KEY' header to its matching ‘END PRIVATE KEY' footer, spanning multiple lines.  |
| FR-03d | The system shall detect MD5, SHA1, and SHA256 hash values based on their fixed hexadecimal length (32, 40, and 64 characters respectively). |
| FR-04 | The system shall produce a Risk Report showing what was found, where (line number), and what type of finding it is. |
| FR-05 | The system shall produce a Redacted Log file where all detected PII and secrets are masked. |
| FR-06 | The system shall reject files that aren't .log or .txt, with a clear error message. |
| FR-07 | The system shall let the user download both the Risk Report and the Redacted Log file. |

## 2. Non-Functional Requirements

| ID | Requirement | Quality Attribute |

| NFR-01 | The system shall process a log file up to 10MB within 5 seconds. | Performance |
| NFR-02 | The system shall correctly catch all common PII formats (like valid emails) during testing, no missed matches. | Reliability |
| NFR-03 | The system shall never send uploaded log files anywhere externally. | Security |
| NFR-04 | The system shall run as a command-line tool that developers can invoke manually, returning a non-zero exit code when secrets or PII are found
, so the scan result can block a git push.  | Usability |
| NFR-05 | The detection logic (regex, entropy rules) shall be kept separate from the GUI code, so rules can be updated on their own. | Maintainability |
| NFR-06 | The system shall run on Windows without needing extra paid tools or accounts. | Portability / Compatibility |
| NFR-07 | The system shall not keep or log the contents of uploaded files after the session ends, unless the user exports them. | Security / Compliance |

