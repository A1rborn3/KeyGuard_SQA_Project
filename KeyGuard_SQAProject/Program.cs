using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KeyGuard_SQAProject
{
    internal static class Program
    {
        private static void PrintUsage()
        {
            Console.WriteLine("Usage: KeyGuard_Scanner <logFilePath> [--out <reportPath>]");
            Console.WriteLine("Scans a log file for likely secrets (emails, keys, hashes, cc numbers, passwords, private keys).");
        }

        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                Console.Write("Enter path to log file: ");
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) return 1;
                args = new[] { input.Trim() };
            }

            string filePath = args[0];
            string? outPath = null;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--out" && i + 1 < args.Length)
                {
                    outPath = args[i + 1];
                    i++;
                }
            }

            try
            {
                Console.WriteLine($"Scanning {filePath} ... (streaming, line-by-line)");
                var findings = new List<Finding>();
                foreach (var f in SecretsScanner.ScanFile(filePath))
                {
                    findings.Add(f);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(f.ToString());
                    Console.ResetColor();
                }

                if (outPath is not null)
                {
                    using var writer = new StreamWriter(outPath, append: false, encoding: Encoding.UTF8);
                    writer.WriteLine($"Scan report for: {filePath}");
                    writer.WriteLine($"Generated: {DateTime.UtcNow:O}");
                    writer.WriteLine($"Findings: {findings.Count}");
                    writer.WriteLine();
                    foreach (var f in findings)
                    {
                        writer.WriteLine($"{f.LineNumber}\t{f.PatternName}\t{f.Masked}");
                    }
                    Console.WriteLine($"Report written to: {outPath}");
                }

                Console.WriteLine($"Scan complete. {findings.Count} potential secrets found.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
                return 2;
            }
        }
    }
}
