# Continuous Improvement

## What Worked Well
Cross checking our documentation against the code and tests caught real mismatches. Keeping detection, masking and Luhn logic in separate classes made each part easy to test on its own.

## What Did Not Work Well
Some requirement wording was too vague to test, such as "or similar" and "multiple lines". The first draft also described detection techniques the code did not use.

## Root Cause of One Issue
The requirements were first written in general terms, so they did not match the exact regex patterns that were implemented.

## Improvement Action
Write requirements with exact keywords, formats and limits, and re-check them against the code after every change.

## How We Will Check the Improvement
Review the RTM after each change and confirm every requirement has a test case with a matching expected result.

## Agile and DevOps Quality Practices for This Project

| Practice | How It Could Be Used in This Project |
|:--|:--|
| Sprint planning | Pick a small set of patterns and tests per week |
| Daily stand-up | Quick check on progress, blockers and failing tests |
| Definition of Done | A pattern is done only when coded, tested, documented and added to the RTM |
| Continuous Integration | Run all tests automatically on every push to GitHub |
| Regression testing | Re-run every test after adding or changing a pattern |
| Retrospective | Review at the end of each phase what worked and what to improve |
