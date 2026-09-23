# Proposed Solution and Initial Prototype

## How the Solution Addresses the Problem

The problem identified in Task 1 is that developers frequently expose PII and secrets accidentally, either through debug logging or hardcoded values, and that this exposure often isn't caught until after the code has already been pushed to a shared repository or logging system. KeyGuard addresses this directly by giving developers a way to check their own files locally, before that push happens, shifting the point of detection as early as possible in the workflow rather than relying on manual review or catching the leak after the fact.

The tool works by scanning a specified file for known patterns associated with sensitive data, email addresses, phone numbers, AWS credentials, password assignments, private key blocks, and cryptographic hashes, plus credit-card-shaped numbers validated with a checksum to reduce false alarms. Every finding is masked before being shown or saved, so running the scan itself never exposes the very data it's trying to protect. If anything is found, the tool signals this clearly (via console output and a non-zero exit code), which is designed specifically so it can be wired into a pre-commit hook and block a `git push` automatically if a secret is detected.

## Initial Prototype

The initial prototype, `KeyGuard_SQAProject`, is a C# .NET console application structured around a small number of focused components:

- **`SecretsScanner.cs`** — the core scanning engine, reads a file line by line and checks each line against a list of defined patterns
- **`Pattern.cs`** — represents a single detection rule (a name, a regex, and whether Luhn validation applies)
- **`Luhn.cs`** — implements the Luhn checksum algorithm, used to validate credit-card-shaped numbers and reduce false positives
- **`Masking.cs`** — masks any detected value before it's displayed or saved, showing only the first and last few characters
- **`Finding.cs`** — represents a single detected result, including line number, pattern name, and the masked value
- **`Program.cs`** — the CLI entry point, accepts a file path (via argument or interactive prompt) and an optional `--out` flag to export a report

This prototype currently demonstrates the main intended functionality end to end: a user can point the tool at a `.log` or `.txt` file, and it will scan the file, report findings to the console with their masked values, and optionally write those findings to a report file. File-type and missing-file validation are also already implemented, so the tool fails clearly and predictably rather than crashing on bad input.

## Interface Decision: Command-Line Interface, Not a GUI

The team deliberately chose a command-line interface instead of a GUI, and this decision was made early, before implementation began.

**Why a GUI is not appropriate for this tool:** KeyGuard's intended users are developers and engineers, not general end users, and its intended point of use is inside an existing developer workflow, specifically, running automatically (or manually) before a `git push`, similar to how tools like GitLeaks or a pre-commit linter operate. A GUI would work against this use case rather than support it, it would require a user to manually open an application and interact with it outside their normal terminal-based workflow, which adds friction to exactly the kind of fast, automatic check this tool is meant to provide. Tools designed to fit into this space, such as GitLeaks, pip, or zoxide, are consistently CLI-based for this same reason.

**Why the CLI is the right alternative:** a CLI tool can be invoked directly, scripted, and wired into automation (such as a Git pre-commit hook) without any manual interaction required. It can also return a clear, machine-readable exit code (zero for a clean scan, non-zero when findings exist), which is exactly the signal a pre-commit hook needs to decide whether to allow or block a push. This aligns directly with NFR-04 from Task 2, which defines usability for this project specifically in terms of clear, scriptable CLI output rather than a beginner-friendly graphical interface.

## Next Steps for the Prototype

As noted in Task 7, the prototype currently only accepts `.log` and `.txt` files and does not yet support scanning multiple files across a directory in a single run. Expanding file type support and directory-level scanning is planned for the next phase, building on the same CLI-first design established in this initial prototype.