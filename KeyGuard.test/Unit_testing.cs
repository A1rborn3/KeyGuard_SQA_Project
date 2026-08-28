using KeyGuard_SQAProject;
using System;
using System.Collections.Generic;
using System.Text;

namespace KeyGuard.test
{
    [TestClass]
    public sealed class UnitTesting
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

        //Masking testing inline with masking acceptance criteria
        [TestMethod]
        public void MaskPII_ReplacesPIIWithStars()
        {
            //less than minimum length, should return only astrisks
            Assert.AreEqual("********", Masking.Mask("abcd1234"));
            Assert.AreEqual("****", Masking.Mask("abcd"));
            //longer lengths, should return the first 4 and last 4 characters with stars in between
            Assert.AreEqual("abcd******4567", Masking.Mask("abcdefg1234567"));
            Assert.AreEqual("asdf************************************4321", Masking.Mask("asdfghjklqwertyuiopzxcvbnm123456789987654321"));
            //special chars handling (including asterisks at edge)
            Assert.AreEqual("asdf*********)-+", Masking.Mask("asdf!@#$%^&(*)-+"));

        }
    }
}
