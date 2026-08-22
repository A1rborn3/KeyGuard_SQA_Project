## Scope of Testing

Core detection logic: email, phone number, AWS Access Key, password, private key block and hash pattern matching.
Credit card checksum validation (Luhn algorithm).
Masking logic: ensuring findings are never shown in saved file in full.
File scanning behaviour: include line by line reading and handle invalid files.
CLI behaviour: prevent git push when there is a finding.
Report output correctness.

## Out-of-Scope Items (Currently)

Integration with actual Git.
Performance testing under extremely large files (1GB+ logs).
Detection of other secret types that is not yet included (but may be added in the future).
Non-English log content.

## Relevant Test Levels or Test Types

**Unit Testing**
Core logic can be tested in isolation (Luhn, Regex patterns).

**Integration Testing**
All pattern scanners need to be tested together against real sample files to ensure integration between each scanner works seamlessly.

**System Testing**
Run the compiled CLI tool end to end against a sample file and check console output, before the user does any commit.

**Acceptance Testing**
Verifying that acceptance criteria defined in the docs are met.

**Regression Testing**
Detection patterns will likely be added or adjusted, existing tests need to be re-run after every change to confirm nothing is broken.

**Usability Testing**
Tool is only available in CLI, usability testing will mean clear output and action.

**Security Testing**
Confirming masking is applied consistently and no secret value can leak.

**Performance Testing**
Basic check that scanning completes in a reasonable time for typical log file sizes.

## Functional Testing Approach

Focus on confirming each detection pattern correctly identifies its target and ignores content that doesn't match its pattern. This will be done using real log files that the team owns, planting each finding type in them (email, AWS key, etc.). The scanner will scan this file and the result will be checked against the expected outcome to confirm findings are caught. Unit level tests will isolate individual components first.

## Non-Functional Testing Approach

Every unit test that produces a finding and saves it will assert that the masked value never equals the raw value.
False positive reduction can be tested by feeding the pattern both a Luhn-valid and invalid number, confirming only the valid one is reported.
Manual check will be done by timing a scan against log files (with a few thousand lines) to confirm scan time is reasonable.
Confirming new patterns can be added into the scanner without needing to modify other components.

## Entry Criteria

Testing can begin when:
- The solution builds successfully with no compile errors.
- The requirements and acceptance criteria are finalised.
- Test project (KeyGuard.test) is set up and referencing the main project.

## Exit Criteria

Testing is completed when:
- All planned unit and integration tests pass.
- All required test cases are implemented and passing.
- No known critical defect exists where a real secret or PII value could be exposed unmasked.
- The CLI correctly returns findings, confirmed by at least one system level test.

## Test Environment, Tools, Devices, Platforms, or Dependencies

Language and Framework: C#, .NET.
Test framework: MSTest.
IDE: Visual Studio.
Test project: KeyGuard.test, referencing the main project.
Operating system: Windows.
Test data: A dedicated sample log file (e.g. test.txt) containing one planted example of each finding type, used consistently across integration tests so results are repeatable.
Version control: GitHub.
