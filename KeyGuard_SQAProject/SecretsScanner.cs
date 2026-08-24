using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace KeyGuard_SQAProject
{
    internal static class SecretsScanner
    {
        public static readonly List<Pattern> Patterns = new()
        {
            new Pattern("Email", @"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
            new Pattern("AWS Access Key ID", @"\bAKIA[0-9A-Z]{16}\b"),
            new Pattern("Base64-like token", @"\b[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}\b"),
            new Pattern("MD5 Hash", @"\b[a-f0-9]{32}\b"),
            new Pattern("SHA1 Hash", @"\b[a-f0-9]{40}\b"),
            new Pattern("SHA256 Hash", @"\b[a-f0-9]{64}\b"),
            new Pattern("Password assignment", @"\b(password|passwd|pwd|secret)\b\s*[:=]\s*['""]?([^\s'""]{4,})['""]?"),
            // changed to tighten requirements for phone numbers to avoid false positives, now requires 10 digits in total with optional country code. this will avoid double matches with cc
            new Pattern("Phone", @"(?<!\d)(?:\+?\d{1,3}[\s\-]?)?(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]?\d{4}(?!\d)"),
            new Pattern("Credit Card (possible)", @"\b(?:\d[ \-]*?){13,19}\b", useLuhn: true),
            new Pattern("Private Key Header", @"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
        };

        public static IEnumerable<Finding> ScanFile(string path)
        {
            //fast path validation
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);
            if (!path.EndsWith(".txt") && !path.EndsWith(".log")) throw new ArgumentException("Invalid file type, only .txt and .log files are supported", nameof(path));
            return ScanFileIterator(path);
        }

        public static IEnumerable<Finding> ScanFileIterator(string path)
        {
            
            using var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

            string? line;
            long lineNumber = 0;
            bool inPrivateKeyBlock = false;
            var privateKeyBuffer = new StringBuilder();
            long privateKeyStartLine = 0;

            while ((line = sr.ReadLine()) != null)
            {
                lineNumber++;

                if (inPrivateKeyBlock)
                {
                    privateKeyBuffer.AppendLine(line);
                    if (line.Contains("-----END") && line.Contains("PRIVATE KEY-----"))
                    {
                        inPrivateKeyBlock = false;
                        yield return new Finding
                        {
                            LineNumber = privateKeyStartLine,
                            PatternName = "Private Key Block",
                            RawMatch = privateKeyBuffer.ToString()
                        };
                        privateKeyBuffer.Clear();
                    }
                    continue;
                }

                if (line.Contains("-----BEGIN") && line.Contains("PRIVATE KEY-----"))
                {
                    inPrivateKeyBlock = true;
                    privateKeyStartLine = lineNumber;
                    privateKeyBuffer.AppendLine(line);
                    continue;
                }

                foreach (var p in Patterns)
                {
                    foreach (Match m in p.Regex.Matches(line))
                    {
                        string matched = m.Value;
                        if (p.Name == "Password assignment" && m.Groups.Count >= 3 && !string.IsNullOrEmpty(m.Groups[2].Value))
                        {
                            matched = m.Groups[2].Value;
                        }

                        if (p.UseLuhnForDigits)
                        {
                            var digits = Regex.Replace(matched, @"\D", "");
                            if (digits.Length >= 13 && digits.Length <= 19 && Luhn.IsValid(digits))
                            {
                                yield return new Finding { LineNumber = lineNumber, PatternName = p.Name, RawMatch = digits };
                            }
                        }
                        else
                        {
                            yield return new Finding { LineNumber = lineNumber, PatternName = p.Name, RawMatch = matched };
                        }
                    }
                }
            }
        }
    }
}