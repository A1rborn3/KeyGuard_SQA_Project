# KeyGuard

A command line tool that scans .log and .txt files for secrets and PII before you push to Git.

## What it detects
Emails, phone numbers, AWS access keys, password and secret assignments, private key blocks, MD5/SHA1/SHA256 hashes, and credit card numbers (checked with the Luhn algorithm).

## Usage
KeyGuard_Scanner <logFilePath> [--out <reportPath>]

Findings are masked before they are shown or saved.

## Documentation
Everything for the project report is in the docs folder.

## Tests
Unit and integration tests are in the KeyGuard.test project (MSTest).