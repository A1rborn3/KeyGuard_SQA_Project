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
            Console.WriteLine("Usage: KeyGuard_Scanner <fileOrDirectoryPath> [--out <reportPath>]");
            Console.WriteLine("Scans a .log or .txt file, or supported files in a directory, for likely secrets.");
        }

        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                Console.Write("Enter path to file or directory: ");
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
                bool isDirectory = Directory.Exists(filePath);
                Console.WriteLine(isDirectory
                    ? $"Scanning directory {filePath} ..."
                    : $"Scanning {filePath} ... (streaming, line-by-line)");

                var findings = new List<Finding>();
                if (isDirectory)
                {
                    findings.AddRange(
                        DirectorySorter.ScanDirectory(filePath)
                            .SelectMany(result => result.Findings));
                }
                else
                {
                    findings.AddRange(SecretsScanner.ScanFile(filePath));
                }

                foreach (var finding in findings)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(finding.ToString());
                    Console.ResetColor();
                }

                if (outPath is not null)
                {
                    using var writer = new StreamWriter(outPath, append: false, encoding: Encoding.UTF8);
                    writer.WriteLine($"Scan report for: {filePath}");
                    writer.WriteLine($"Generated: {DateTime.UtcNow:O}");
                    writer.WriteLine($"Findings: {findings.Count}");
                    writer.WriteLine();
                    foreach (var finding in findings)
                    {
                        var filePrefix = isDirectory ? $"{finding.FilePath}\t" : string.Empty;
                        writer.WriteLine($"{filePrefix}{finding.LineNumber}\t{finding.PatternName}\t{finding.Masked}");
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
