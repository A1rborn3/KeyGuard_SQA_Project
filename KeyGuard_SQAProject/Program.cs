using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KeyGuard_SQAProject
{
    internal static class Program
    {
        private static void PrintUsage() // Prints usage instructions to the console
        {
            Console.WriteLine("Usage: KeyGuard_Scanner <fileOrDirectoryPath> [--out <reportPath>]"); 
            Console.WriteLine("Scans a .log or .txt file, or supported files in a directory, for likely secrets.");
        }

        private static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                Console.Write("Enter path to file or directory: "); // Prompt user for input if no arguments are provided
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
                    outPath = args[i + 1];// Set output path for report if --out flag is provided
                    i++;
                }
            }

            try
            {
                bool isDirectory = Directory.Exists(filePath);
                Console.WriteLine(isDirectory
                    ? $"Scanning directory {filePath} ..."
                    : $"Scanning {filePath} ... (streaming, line-by-line)");// Inform user about current scanning process

                var findings = new List<Finding>();
                if (isDirectory)
                {
                    findings.AddRange(
                        DirectorySorter.ScanDirectory(filePath)
                            .SelectMany(result => result.Findings));// Scan the directory and collect findings from all files
                }
                else
                {
                    findings.AddRange(SecretsScanner.ScanFile(filePath));
                }

                foreach (var finding in findings)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(finding.ToString());
                    Console.ResetColor();// Print each finding in red to the console
                }

                if (outPath is not null)
                {
                    using var writer = new StreamWriter(outPath, append: false, encoding: Encoding.UTF8);
                    writer.WriteLine($"Scan report for: {filePath}");
                    writer.WriteLine($"Generated: {DateTime.UtcNow:O}");
                    writer.WriteLine($"Findings: {findings.Count}");
                    writer.WriteLine();// Write report header to the output file
                    foreach (var finding in findings)
                    {
                        var filePrefix = isDirectory ? $"{finding.FilePath}\t" : string.Empty;
                        writer.WriteLine($"{filePrefix}{finding.LineNumber}\t{finding.PatternName}\t{finding.Masked}");// Write each finding to the output file with tab-separated values
                    }
                    Console.WriteLine($"Report written to: {outPath}");// Inform user about the report file location
                }

                Console.WriteLine($"Scan complete. {findings.Count} potential secrets found.");// Inform user about the total number of findings
                return 0;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;// Set console text color to yellow for error message
                Console.WriteLine($"Error: {ex.Message}");// Print error message to the console
                Console.ResetColor();
                return 2;
            }
        }
    }
}
