# Risk Register

| Risk | Likelihood | Impact | Priority | Mitigation |
|:--|:--|:--|:--|:--|
| A real secret is missed (false negative) | Medium | High | High | Add more regex patterns, test with a wide variety of planted secrets, measure recall |
| Too many false positives cause developers to ignore results | Medium | Medium | Medium | Use checksums and tighter patterns, review results after each pattern change |
| Unclosed private key block is never reported (DEF-004) | Low | High | High | Add a line limit and report an unclosed block |
| Scan too slow on large files, blocking the developer | Low | Medium | Medium | Time a 10MB file against NFR-01 and keep line by line streaming |
| Only .txt and .log files are supported, so secrets in other files are missed | High | Medium | High | Add .json, .env and code file support in the next phase |
| Documentation drifts away from the code | Medium | Medium | Medium | Re-check requirements and the RTM after every change |