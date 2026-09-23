using KeyGuard_SQAProject;
using System;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeyGuard.test
{
    [TestClass]
    public sealed class IntegrationTesting
    {

        private static readonly string TestFilesDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "TestingFiles"));
        private string _directorySorterTestPath = null!;

        // Create an isolated temporary directory before each test.
        [TestInitialize]
        public void SetupDirectorySorterTestDirectory()
        {
            _directorySorterTestPath = Path.Combine(
                Path.GetTempPath(),
                "DirectorySorterTests",
                Guid.NewGuid().ToString());

            Directory.CreateDirectory(_directorySorterTestPath);
        }

        // Remove temporary files after each test.
        [TestCleanup]
        public void CleanupDirectorySorterTestDirectory()
        {
            if (Directory.Exists(_directorySorterTestPath))
            {
                Directory.Delete(_directorySorterTestPath, recursive: true);
            }
        }

        // Integration test: missing file should throw FileNotFoundException with expected message
        [TestMethod]
        public void ScanFile_MissingFile_ThrowsFileNotFound_WithMessage()
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".txt"); // guaranteed missing path

            var ex = Assert.Throws<FileNotFoundException>(() =>
                SecretsScanner.ScanFile(path) 
            );

            StringAssert.Contains(ex.Message, "File not found");
            Assert.AreEqual(path, ex.FileName);
        }

        [TestMethod]
        public void ScanFile_ExistingFile_WrongFileType_ThrowsArgumentException_WithMessage()
        { 
            // locate the TestingFiles folder relative to the test assembly output directory
            var path = Path.Combine(TestFilesDir, "ReadMe.md");

            // sanity check
            Assert.IsTrue(File.Exists(path), $"Test file not found at expected location: {path}");

            var ex = Assert.Throws<ArgumentException>(() =>
                SecretsScanner.ScanFile(path)
            );

            StringAssert.Contains(ex.Message, "Invalid file type");
            Assert.AreEqual("path", ex.ParamName);
        }

        [TestMethod]
        public void ScanFile_ExistingFile_ValidFileType_ReturnsFindings()
        {
            // locate the TestingFiles folder relative to the test assembly output directory
            var path = Path.Combine(TestFilesDir, "empty.txt");
            // sanity check
            Assert.IsTrue(File.Exists(path), $"Test file not found at expected location: {path}");
            var findings = SecretsScanner.ScanFile(path);
            // Assert that findings are returned and contain expected patterns
            Assert.IsNotNull(findings);
            CollectionAssert.AllItemsAreNotNull(new List<Finding>(findings));

            var path2 = Path.Combine(TestFilesDir, "empty.log");
            // sanity check
            Assert.IsTrue(File.Exists(path2), $"Test file not found at expected location: {path2}");
            var findings2 = SecretsScanner.ScanFile(path2);
            // Assert that findings are returned and contain expected patterns
            Assert.IsNotNull(findings2);
            CollectionAssert.AllItemsAreNotNull(new List<Finding>(findings2));
        }

        [TestMethod]
        public void ScanFile_ExistingFile_ValidFileTypeWithSecrets_ReturnsFindings()
        {
            // locate the TestingFiles folder relative to the test assembly output directory
            var path = Path.Combine(TestFilesDir, "Secrets.log");
            // sanity check
            Assert.IsTrue(File.Exists(path), $"Test file not found at expected location: {path}");
            var findings = SecretsScanner.ScanFile(path);
            // Assert that findings are returned and contain expected patterns
            Assert.IsNotNull(findings);
            var findingsList = new List<Finding>(findings);

            // Expecting 10 findings in the exact order they appear in the file
            Assert.HasCount(10, findingsList, "Expected 10 findings from the test file.");

            Assert.AreEqual("Email", findingsList[0].PatternName);
            Assert.AreEqual("alice@example.com", findingsList[0].RawMatch);

            Assert.AreEqual("AWS Access Key ID", findingsList[1].PatternName);
            Assert.AreEqual("AKIA1234567890ABCDfh", findingsList[1].RawMatch);

            Assert.AreEqual("Base64-like token", findingsList[2].PatternName);
            Assert.AreEqual("abcdefghijklmnopqrst.ABCDEFGHIJKLMNOPQRST", findingsList[2].RawMatch);

            Assert.AreEqual("MD5 Hash", findingsList[3].PatternName);
            Assert.AreEqual("d41d8cd98f00b204e9800998ecf8427e", findingsList[3].RawMatch);

            Assert.AreEqual("Password assignment", findingsList[4].PatternName);
            Assert.AreEqual("s3cr3t!", findingsList[4].RawMatch);

            Assert.AreEqual("Password assignment", findingsList[5].PatternName);
            Assert.AreEqual("secret", findingsList[5].RawMatch);

            Assert.AreEqual("Password assignment", findingsList[6].PatternName);
            Assert.AreEqual("s3cr3t!", findingsList[6].RawMatch);

            Assert.AreEqual("Phone", findingsList[7].PatternName);
            Assert.AreEqual("+1 (555) 123-4567", findingsList[7].RawMatch);

            Assert.AreEqual("Credit Card (possible)", findingsList[8].PatternName);
            // scanner returns digits-only when using Luhn validation
            Assert.AreEqual("4539148803436467", findingsList[8].RawMatch);

            Assert.AreEqual("Private Key Block", findingsList[9].PatternName);
            // the private key block RawMatch should include begin and end markers
            StringAssert.Contains(findingsList[9].RawMatch, "-----BEGIN PRIVATE KEY-----");
            StringAssert.Contains(findingsList[9].RawMatch, "-----END PRIVATE KEY-----");

            // future test case, validate the lines are printed correctly ( to find line nums run the pwsh script as it prints them to console)
        }

        [TestMethod]
        public void ScanFile_ExistingFile_ValidFileTypeWithSecrets_ReturnsLineNumbers()
        {
            // locate the TestingFiles folder relative to the test assembly output directory
            var path = Path.Combine(TestFilesDir, "Secrets.log");
            // sanity check
            Assert.IsTrue(File.Exists(path), $"Test file not found at expected location: {path}");
            var findings = SecretsScanner.ScanFile(path);
            // Assert that findings are returned and contain expected patterns
            Assert.IsNotNull(findings);
            var findingsList = new List<Finding>(findings);

            // Expecting 10 findings in the exact order they appear in the file
            Assert.HasCount(10, findingsList, "Expected 10 findings from the test file.");

            Assert.AreEqual("Email", findingsList[0].PatternName);
            Assert.AreEqual(7, findingsList[0].LineNumber);

            Assert.AreEqual("AWS Access Key ID", findingsList[1].PatternName);
            Assert.AreEqual(296, findingsList[1].LineNumber);

            Assert.AreEqual("Base64-like token", findingsList[2].PatternName);
            Assert.AreEqual(758, findingsList[2].LineNumber);

            Assert.AreEqual("MD5 Hash", findingsList[3].PatternName);
            Assert.AreEqual(1046, findingsList[3].LineNumber);

            Assert.AreEqual("Password assignment", findingsList[4].PatternName);
            Assert.AreEqual(1749, findingsList[4].LineNumber);

            Assert.AreEqual("Password assignment", findingsList[5].PatternName);
            Assert.AreEqual(1850, findingsList[5].LineNumber);

            Assert.AreEqual("Password assignment", findingsList[6].PatternName);
            Assert.AreEqual(1937, findingsList[6].LineNumber);

            Assert.AreEqual("Phone", findingsList[7].PatternName);
            Assert.AreEqual(2416, findingsList[7].LineNumber);

            Assert.AreEqual("Credit Card (possible)", findingsList[8].PatternName);
            // scanner returns digits-only when using Luhn validation
            Assert.AreEqual(2819, findingsList[8].LineNumber);

            Assert.AreEqual(3387, findingsList[9].LineNumber);

            // to find raw info run the pwsh script as it prints them to console)
            // next tests to check masking output
        }

        [TestMethod]
        public void ScanDirectory_SupportedFiles_ReturnsFindings()
        {
            // Verify that .txt and .log files are discovered and scanned.
            var textFile = Path.Combine(_directorySorterTestPath, "credentials.txt");
            var logFile = Path.Combine(_directorySorterTestPath, "application.log");

            File.WriteAllText(textFile, "email=test@example.com");
            File.WriteAllText(logFile, "password=secret123");

            var results = DirectorySorter
                .ScanDirectory(_directorySorterTestPath)
                .ToList();

            Assert.IsTrue(
                results.Any(result => result.FilePath == textFile),
                "The .txt file should be scanned.");

            Assert.IsTrue(
                results.Any(result => result.FilePath == logFile),
                "The .log file should be scanned.");

            var findings = results
                .SelectMany(result => result.Findings)
                .ToList();

            Assert.IsTrue(
                findings.Any(finding =>
                    finding.PatternName == "Email" &&
                    finding.RawMatch == "test@example.com"),
                "The email secret should be detected.");

            Assert.IsTrue(
                findings.Any(finding =>
                    finding.PatternName == "Password assignment" &&
                    finding.RawMatch == "secret123"),
                "The password secret should be detected.");
        }

        [TestMethod]
        public void ScanDirectory_GitignoredFile_IsNotScannedOrReported()
        {
            // Verify that .gitignore exclusions prevent scanning and reporting.
            var ignoredFile = Path.Combine(_directorySorterTestPath, "ignored.txt");
            var includedFile = Path.Combine(_directorySorterTestPath, "included.txt");

            File.WriteAllText(
                Path.Combine(_directorySorterTestPath, ".gitignore"),
                "ignored.txt");

            File.WriteAllText(ignoredFile, "email=ignored@example.com");
            File.WriteAllText(includedFile, "email=included@example.com");

            var results = DirectorySorter
                .ScanDirectory(_directorySorterTestPath)
                .ToList();

            Assert.IsFalse(
                results.Any(result => result.FilePath == ignoredFile),
                "A .gitignored file must not be scanned.");

            Assert.IsTrue(
                results.Any(result => result.FilePath == includedFile),
                "A non-ignored file should be scanned.");

            var findings = results
                .SelectMany(result => result.Findings)
                .ToList();

            Assert.IsFalse(
                findings.Any(finding => finding.RawMatch == "ignored@example.com"),
                "Secrets from ignored files must not be reported.");

            Assert.IsTrue(
                findings.Any(finding => finding.RawMatch == "included@example.com"),
                "Secrets from included files should be reported.");
        }

        [TestMethod]
        public void ScanDirectory_UnsupportedFiles_AreNotReturned()
        {
            // Verify that unsupported file types are skipped completely.
            File.WriteAllText(
                Path.Combine(_directorySorterTestPath, "documentation.md"),
                "email=markdown@example.com");

            File.WriteAllText(
                Path.Combine(_directorySorterTestPath, "settings.json"),
                "password=jsonSecret123");

            var results = DirectorySorter
                .ScanDirectory(_directorySorterTestPath)
                .ToList();

            Assert.IsEmpty(
                results,
                "Unsupported file types should be skipped completely.");
        }
        [TestMethod]
        public void ScanDirectory_NestedSupportedFile_ReturnsFindings()
        {
            // Verify that supported files in nested directories are discovered and scanned.
            var nestedDirectory = Path.Combine(_directorySorterTestPath, "logs", "archive");
            Directory.CreateDirectory(nestedDirectory);

            var nestedFile = Path.Combine(nestedDirectory, "archived.log");
            File.WriteAllText(nestedFile, "email=nested@example.com");

            var results = DirectorySorter
                .ScanDirectory(_directorySorterTestPath)
                .ToList();

            Assert.IsTrue(
                results.Any(result => result.FilePath == nestedFile),
                "A supported file in a nested directory should be scanned.");

            var findings = results
                .SelectMany(result => result.Findings)
                .ToList();

            Assert.IsTrue(
                findings.Any(finding =>
                    finding.PatternName == "Email" &&
                    finding.RawMatch == "nested@example.com"),
                "The email in the nested file should be detected.");
        }

    }
}
