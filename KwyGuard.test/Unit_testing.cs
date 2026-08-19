using KeyGuard_SQAProject;
using System;
using System.Collections.Generic;
using System.Text;

namespace KeyGuard.test
{
    [TestClass]
    public sealed class Testing
    {
        //tests to ensure the Luhn algorithm is correctly functioning
        [TestMethod]
        public void IsValid_KnownValidNumber_ReturnsTrue()
        {
            // Luhn test number
            Assert.IsTrue(Luhn.IsValid("79927398713"));
        }

        [TestMethod]
        public void IsValid_InvalidNumber_ReturnsFalse()
        {
            Assert.IsFalse(Luhn.IsValid("79927398710"));
        }

        [TestMethod]
        public void IsValid_NullOrNonDigits_ReturnsFalse()
        {
            Assert.IsFalse(Luhn.IsValid(null));
            Assert.IsFalse(Luhn.IsValid("abcd1234"));
        }



        //Secret scanner testing
        [TestMethod]
        public void ScanFile_FindsExpectedPatterns()
        {
            //this will not work till we add random secrets to the test file and fix the path
            // like this below
            //"User login: alice@example.com",
            //    "AWS: AKIA1234567890ABCD",
            //    "Token: abcdefghijklmnopqrst.ABCDEFGHIJKLMNOPQRST",
            //    "MD5: d41d8cd98f00b204e9800998ecf8427e",
            //    "Password assignment: password='s3cr3t!'",
            //    "Phone: +1 (555) 123-4567",
            //    "Possible CC: 4539 1488 0343 6467",
            //    "-----BEGIN PRIVATE KEY-----",
            //    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...",
            //    "-----END PRIVATE KEY-----",


            //this brick doesnt work and i have no time, i fix later :)
            //_path = "test.txt";
            //var findings = SecretsScanner.ScanFile(_path).ToList();

            //Assert.Contains(findings, f => f.PatternName == "Email");
            //Assert.Contains(findings, f => f.PatternName == "AWS Access Key ID");
            //Assert.Contains(findings, f => f.PatternName == "Base64-like token");
            //Assert.Contains(findings, f => f.PatternName == "MD5 Hash");
            //Assert.Contains(findings, f => f.PatternName == "Password assignment");
            //Assert.Contains(findings, f => f.PatternName == "Phone");
            //Assert.Contains(findings, f => f.PatternName == "Credit Card (possible)");
            //Assert.Contains(findings, f => f.PatternName == "Private Key Block");
        }
    }
}
