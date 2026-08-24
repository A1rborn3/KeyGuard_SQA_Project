using KeyGuard_SQAProject;
using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace KeyGuard.test
{
    [TestClass]
    public sealed class IntegrationTesting
    {

        private static readonly string TestFilesDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "TestingFiles"));

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

            // Expecting 8 findings in the exact order they appear in the file
            Assert.HasCount(8, findingsList, "Expected 8 findings from the test file.");

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

            Assert.AreEqual("Phone", findingsList[5].PatternName);
            Assert.AreEqual("+1 (555) 123-4567", findingsList[5].RawMatch);

            Assert.AreEqual("Credit Card (possible)", findingsList[6].PatternName);
            // scanner returns digits-only when using Luhn validation
            Assert.AreEqual("4539148803436467", findingsList[6].RawMatch);

            Assert.AreEqual("Private Key Block", findingsList[7].PatternName);
            // the private key block RawMatch should include begin and end markers
            StringAssert.Contains(findingsList[7].RawMatch, "-----BEGIN PRIVATE KEY-----");
            StringAssert.Contains(findingsList[7].RawMatch, "-----END PRIVATE KEY-----");
        }

    }
}
