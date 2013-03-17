using System;
using System.Text;
using AdaptiveCrypt;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class ModularCryptTest
    {
        [TestFixtureSetUp]
        public void TestFixtureSetUp()
        {
        }

        [TestFixtureTearDown]
        public void TestFixtureTearDown()
        {
        }

        [SetUp]
        public void SetUp()
        {
        }

        [TearDown]
        public void TearDown()
        {
        }

        [TestCase("$$0$$",                   '$', "",  0,  "",         "")]
        [TestCase("$$10$$",                  '$', "",  10, "",         "")]
        [TestCase("$i$10$$",                 '$', "i", 10, "",         "")]
        [TestCase("$i$10$c2FsdA==$",         '$', "i", 10, "c2FsdA==", "")]
        [TestCase("$i$10$c2FsdA==$Y2lwaGVy", '$', "i", 10, "c2FsdA==", "Y2lwaGVy")]
        [TestCase("$i$0$c2FsdA==$Y2lwaGVy",  '$', "i", 0,  "c2FsdA==", "Y2lwaGVy")]
        public void Constructor1_ValidParams_Sucess(string modularCryptFormatStr,
                                                    char   expectedDelim,
                                                    string expectedIdentifier,
                                                    int    expectedWorkFactor,
                                                    string expectedSaltAsBase64,
                                                    string expectedCipherAsBase64)
        {
            var mc = new ModularCrypt(modularCryptFormatStr);
            Assert.AreEqual(expectedDelim,                                    mc.Delim);
            Assert.AreEqual(expectedIdentifier,                               mc.Identifier);
            Assert.AreEqual(expectedWorkFactor,                               mc.WorkFactor);
            Assert.AreEqual(Convert.FromBase64String(expectedSaltAsBase64),   mc.Salt);
            Assert.AreEqual(Convert.FromBase64String(expectedCipherAsBase64), mc.Cipher);
            Assert.AreEqual(modularCryptFormatStr,                            mc.ToString());
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase(" ")]
        [TestCase("\t")]
        [TestCase("$")]
        [TestCase("$$")]
        [TestCase("$$$")]
        [TestCase("$$$$")]
        [TestCase("$$$$$")]
        [TestCase("$scheme")]
        [TestCase("$scheme$")]
        [TestCase("$scheme$workFactor")]
        [TestCase("$scheme$10")]
        [TestCase("$scheme$10$")]
        [TestCase("$scheme$10$salt")]
        [TestCase("$scheme$10$salt$cipher")]
        public void Constructor1_InvalidParams_ArgumentExceptionThrown(string modularCryptFormatStr)
        {
            Assert.Throws<ArgumentException>(() => new ModularCrypt(modularCryptFormatStr));
        }

        [TestCase('$', "",  10, "",         "",         "$$10$$")]
        [TestCase('$', "",  10, "c2FsdA==", "",         "$$10$c2FsdA==$")]
        [TestCase('$', "i", 10, "c2FsdA==", "Y2lwaGVy", "$i$10$c2FsdA==$Y2lwaGVy")]
        public void Constructor2_ValidParams_Sucess(char   delim,
                                                    string identifier,
                                                    int    workFactor,
                                                    string saltAsBase64,
                                                    string cipherAsBase64,
                                                    string expectedToString)
        {
            byte[] salt   = saltAsBase64   == null ? null : Convert.FromBase64String(saltAsBase64);
            byte[] cipher = cipherAsBase64 == null ? null : Convert.FromBase64String(cipherAsBase64);

            var mc = new ModularCrypt(delim,
                                      identifier,
                                      workFactor,
                                      salt,
                                      cipher);

            Assert.AreEqual(delim,            mc.Delim);
            Assert.AreEqual(identifier,       mc.Identifier);
            Assert.AreEqual(workFactor,       mc.WorkFactor);
            Assert.AreEqual(salt,             mc.Salt);
            Assert.AreEqual(cipher,           mc.Cipher);
            Assert.AreEqual(expectedToString, mc.ToString());
        }

        [TestCase('A', "i",  10, "c2FsdA==", "Y2lwaGVy")]
        [TestCase('$', null, 10, "c2FsdA==", "Y2lwaGVy")]
        [TestCase('S', "i",  -1, "c2FsdA==", "Y2lwaGVy")]
        [TestCase('S', "i",  10, null,       "Y2lwaGVy")]
        [TestCase('S', "i",  10, "c2FsdA==", null)]
        public void Constructor2_InvalidParams_ArgumentExceptionThrown(char   delim,
                                                                       string identifier,
                                                                       int    workFactor,
                                                                       string saltAsString,
                                                                       string cipherAsString)
        {
            byte[] salt   = saltAsString   == null ? null : Convert.FromBase64String(saltAsString);
            byte[] cipher = cipherAsString == null ? null : Convert.FromBase64String(cipherAsString);

            Assert.Throws<ArgumentException>(() => new ModularCrypt(delim,
                                                                    identifier,
                                                                    workFactor,
                                                                    salt,
                                                                    cipher));
        }
    }
}