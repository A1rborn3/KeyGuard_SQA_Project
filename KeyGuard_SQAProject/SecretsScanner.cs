using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KeyGuard_SQAProject
{
    // Holds the file extensions that the scanner is allowed to inspect.
    // This lets us keep the supported formats configurable without hard-coding them into the scanning logic.
    internal class ScannerConfig
    {
        [JsonPropertyName("supportedFileTypes")]
        public HashSet<string> SupportedFileTypes { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    // Scans a file line-by-line and reports suspicious secret-like values using a set of regex-based detectors.
    // The scanner is intentionally conservative: it looks for common credential patterns and key material that
    // should be flagged during review, while still allowing the supported file set to be adjusted via config.json.
    internal static class SecretsScanner
    {
        // Load the configuration once when the application starts so every scan uses the same accepted extensions.
        internal static readonly ScannerConfig config = LoadConfig();

        // Reads the optional config file, falling back to a default set of plain-text extensions if it is missing or malformed.
        private static ScannerConfig LoadConfig()
        {
            if (File.Exists("config.json"))
            {
                try
                {
                    return JsonSerializer.Deserialize<ScannerConfig>(File.ReadAllText("config.json")) ?? new ScannerConfig();
                }
                catch (JsonException)
                {
                    Console.WriteLine("Error reading config.json. Using default config.");
                }
            }

            // A minimal default keeps the scanner usable even when no config is provided.
            var defaultConfig = new ScannerConfig
            {
                SupportedFileTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    ".txt",
                    ".log"
                }
            };

            File.WriteAllText("config.json", JsonSerializer.Serialize(defaultConfig, new JsonSerializerOptions { WriteIndented = true }));
            Console.Write("Config not found. Default config with .txt and .log used");
            return defaultConfig;
        }

        // These patterns are ordered from high-confidence identifiers to broader heuristics.
        // The regexes are intentionally tuned to catch common secret formats while reducing noisy matches.
        public static readonly List<Pattern> Patterns = new()
        {
            new Pattern("Email", @"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
            new Pattern("AWS Access Key ID", @"\b(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b"),
            new Pattern("Base64-like token", @"\b[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}\b"),
            new Pattern("MD5 Hash", @"\b[a-f0-9]{32}\b"),
            new Pattern("SHA1 Hash", @"\b[a-f0-9]{40}\b"),
            new Pattern("SHA256 Hash", @"\b[a-f0-9]{64}\b"),
            new Pattern("Password assignment", @"\b(password|passwd|pwd|secret)\b\s*[:=]\s*['""]?([^\s'""]{4,})['""]?"),
            new Pattern("Phone", @"(?<!\d)(?:\+?\d{1,3}[\s\-]?)?(?:\(\d{3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]?\d{4}(?!\d)"),
            new Pattern("Credit Card (possible)", @"\b(?:\d[ \-]*?){13,19}\b", useLuhn: true),
            new Pattern("Private Key Block", @"-----BEGIN (?:RSA )?PRIVATE KEY-----\s*(?:[A-Za-z0-9+/=]+\s*){1,100}-----END (?:RSA )?PRIVATE KEY-----")
        };

        // Validates that the caller is allowed to scan the target file before opening it.
        // This prevents accidental scanning of unsupported files and keeps the behavior explicit.
        public static IEnumerable<Finding> ScanFile(string path)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("File not found", path);

            if (!config.SupportedFileTypes.Contains(Path.GetExtension(path)))
                throw new ArgumentException("Invalid file type", nameof(path));

            return ScanFileIterator(path);
        }

        // Reads the file one line at a time and applies each regex to every line.
        // For private key blocks, we hold a multiline buffer until the closing marker is found so the entire PEM section is reported as one finding.
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

                // PEM-formatted private keys are multi-line blocks, so we capture the full section instead of trying to detect it on a single line.
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

                        // The password pattern captures both the key name and the actual value.
                        // We report only the value to keep the finding focused on the secret itself.
                        if (p.Name == "Password assignment" && m.Groups.Count >= 3 && !string.IsNullOrEmpty(m.Groups[2].Value))
                        {
                            matched = m.Groups[2].Value;
                        }

                        if (p.UseLuhnForDigits)
                        {
                            // Some card-number matches are only valid if they pass the Luhn checksum check.
                            var digits = Regex.Replace(matched, @"\D", "");
                            if (digits.Length >= 13 && digits.Length <= 19 && Luhn.IsValid(digits))
                            {
                                yield return new Finding { LineNumber = lineNumber, PatternName = p.Name, RawMatch = digits, FilePath = path };
                            }
                        }
                        else
                        {
                            yield return new Finding { LineNumber = lineNumber, PatternName = p.Name, RawMatch = matched, FilePath = path };
                        }
                    }
                }
            }
        }
    }
}