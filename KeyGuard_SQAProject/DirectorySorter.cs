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

        // Scans the input directory and notes all files which are not excluded by a given gitignore file
        // runs each file through secrect scanner
        public static IEnumerable<FileScanResult> ScanDirectory(string rootPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath)) throw new ArgumentException("rootPath is required", nameof(rootPath));
            if (!Directory.Exists(rootPath)) throw new DirectoryNotFoundException(rootPath); //validates the root path exists

            var gitignorePath = Path.Combine(rootPath, ".gitignore");
            var patterns = new List<(string Pattern, bool IsNegation)>();
            if (File.Exists(gitignorePath))
            //checks to see if a .gitignore file exists in the root directory
            {
                foreach (var raw in File.ReadAllLines(gitignorePath))
                {
                    var line = raw.Trim();
                    if (string.IsNullOrEmpty(line)) continue;
                    if (line.StartsWith("#")) continue;
                    bool neg = line.StartsWith("!");
                    if (neg) line = line.Substring(1);
                    patterns.Add((line, neg));
                } //saves all gitignore patterns to a list
            }
            else
            {
                Console.WriteLine($"[DirectorySorter] No .gitignore found at {gitignorePath}; scanning all files (no ignores applied).");
            } //if no .gitignore file is found, all files will be scanned as default

            foreach (var file in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
            {
                // find relative file paths using forward slashes for gitignore matching
                var rel = Path.GetRelativePath(rootPath, file).Replace(Path.DirectorySeparatorChar, '/');

                bool ignored = false;
                foreach (var (pattern, neg) in patterns)
                {
                    if (IsMatch(pattern, rel))
                    {
                        if (neg) ignored = false; else ignored = true;
                    }//if a file matches a pattern it will be ignored
                }

                if (ignored) continue;


                // Reads universal config file to detemind the supported file types. this is to keep all scripts supporting the same files unless overridden
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (!SecretsScanner.config.SupportedFileTypes.Contains(Path.GetExtension(file)))
                {
                    Console.WriteLine($"[DirectorySorter] Skipping unsupported file type '{ext}' for file: {file}");
                    continue;
                }

                var result = new FileScanResult { FilePath = file };
                try
                {//tries to scan all valid files and add findings to to final object. if an error occurs, it will be logged and the scan will continue with the next file
                    foreach (var f in SecretsScanner.ScanFile(file)) result.Findings.Add(f);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[DirectorySorter] Error scanning file {file}: {ex.Message}");
                }//gives proper error message on fail. non-blocking

                yield return result;
            }
        }

        //matches basic gitignore patterns to file paths. basic matching supports most use cases
        //wild card matching, negitive and positive patterns supported. does not support nested .gitignore files, only root .gitignore is read
        //complex patterns are not supported
        private static bool IsMatch(string pattern, string relativePath)
        {
            if (string.IsNullOrEmpty(pattern)) return false;

            // normalise to forward slashes for direct matching
            pattern = pattern.Replace("\\", "/");

            bool directoryPattern = pattern.EndsWith("/");
            if (directoryPattern) pattern = pattern.TrimEnd('/');

            // A slash-terminated pattern without a path matches any directory segment.
            if (!pattern.Contains('/'))
            {
                if (directoryPattern)
                {
                    var pathSegments = relativePath.Split('/');
                    for (int i = 0; i < pathSegments.Length - 1; i++)
                    {
                        if (WildcardMatch(pathSegments[i], pattern)) return true;
                    }

                    return false;
                }

                // Otherwise, match against filename only.
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

            return Regex.IsMatch(text, sb.ToString(), RegexOptions.IgnoreCase); //returns true if the text matches the pattern, false otherwise
        }
    }
}
//limitations. only reads root .gitignore, does not handle nested .gitignore files, allows basic patterns
// TODO. 