using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace KeyGuard_SQAProject
{

    internal class DirectorySorter
    {

        // Result container for a single file scan
        internal sealed class FileScanResult
        {
            public string FilePath { get; init; } = string.Empty;
            public List<Finding> Findings { get; init; } = new();
        }

        // Scans the provided directory for files not excluded by a .gitignore at the root
        // and runs SecretsScanner on supported files (.txt, .log).
        public static IEnumerable<FileScanResult> ScanDirectory(string rootPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath)) throw new ArgumentException("rootPath is required", nameof(rootPath));
            if (!Directory.Exists(rootPath)) throw new DirectoryNotFoundException(rootPath);

            var gitignorePath = Path.Combine(rootPath, ".gitignore");
            var patterns = new List<(string Pattern, bool IsNegation)>();
            if (File.Exists(gitignorePath))
            {
                foreach (var raw in File.ReadAllLines(gitignorePath))
                {
                    var line = raw.Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    if (line.StartsWith("#")) continue;
                    bool neg = line.StartsWith("!");
                    if (neg) line = line.Substring(1);
                    patterns.Add((line, neg));
                }
            }
            else
            {
                Console.WriteLine($"[DirectorySorter] No .gitignore found at {gitignorePath}; scanning all files (no ignores applied).");
            }

            foreach (var file in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
            {
                // compute relative path with forward slashes (gitignore uses '/').
                var rel = Path.GetRelativePath(rootPath, file).Replace(Path.DirectorySeparatorChar, '/');

                bool ignored = false;
                foreach (var (pattern, neg) in patterns)
                {
                    if (IsMatch(pattern, rel))
                    {
                        if (neg) ignored = false; else ignored = true;
                    }
                }

                if (ignored) continue;


                // Only attempt to scan files supported by SecretsScanner to avoid exceptions.
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (!SecretsScanner.config.SupportedFileTypes.Contains(Path.GetExtension(file)))
                {
                    Console.WriteLine($"[DirectorySorter] Skipping unsupported file type '{ext}' for file: {file}");
                    continue;
                }

                var result = new FileScanResult { FilePath = file };
                try
                {
                    foreach (var f in SecretsScanner.ScanFile(file)) result.Findings.Add(f);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DirectorySorter] Error scanning file {file}: {ex.Message}");
                }

                yield return result;
            }
        }

        // Very small subset of gitignore-style matching to satisfy basic use-cases.
        // - lines beginning with '/' are matched against the repository-root relative path
        // - lines without '/' are matched against the filename only
        // - trailing '/' patterns match directories (we test prefix)
        // - no support for character classes, escapes, or complex gitignore features
        private static bool IsMatch(string pattern, string relativePath)
        {
            if (string.IsNullOrEmpty(pattern)) return false;

            // normalise
            pattern = pattern.Replace("\\", "/");

            bool directoryPattern = pattern.EndsWith("/");
            if (directoryPattern) pattern = pattern.TrimEnd('/');

            // if the pattern contains no slash, match against filename only
            if (!pattern.Contains('/'))
            {
                var fileName = Path.GetFileName(relativePath);
                return WildcardMatch(fileName, pattern);
            }

            // if pattern starts with '/', match from repository root (relativePath already relative)
            if (pattern.StartsWith("/")) pattern = pattern.Substring(1);

            if (directoryPattern)
            {
                // directory pattern: check if relativePath starts with pattern + '/'
                return relativePath == pattern || relativePath.StartsWith(pattern + "/");
            }

            // otherwise match full relative path against wildcard
            return WildcardMatch(relativePath, pattern);
        }

        private static bool WildcardMatch(string text, string pattern)
        {
            // translate a simple wildcard pattern (* and ?) into regex
            var sb = new StringBuilder();
            sb.Append('^');
            for (int i = 0; i < pattern.Length; i++)
            {
                var c = pattern[i];
                if (c == '*')
                {
                    // collapse consecutive *
                    if (i + 1 < pattern.Length && pattern[i + 1] == '*')
                    {
                        // treat ** as match-any including '/'
                        sb.Append(".*");
                        i++; // skip next *
                    }
                    else
                    {
                        // * matches anything except '/'
                        sb.Append("[^/]*");
                    }
                }
                else if (c == '?') sb.Append('.') ;
                else sb.Append(Regex.Escape(c.ToString()));
            }
            sb.Append('$');

            return Regex.IsMatch(text, sb.ToString(), RegexOptions.IgnoreCase);
        }
    }
}
//limitations. only reads root .gitignore, does not handle nested .gitignore files, allows basic patterns
// TODO. build test cases for this, 