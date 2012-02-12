﻿using AdaptiveCrypt;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class ModularCryptTest
    {
        [SetUp]
        public void SetUp()
        {
        }

        [TearDown]
        public void TearDown()
        {
        }
        
        [TestCase("$$10$",                  '$', "",       10, "",     null,     "$$10$$")]
        [TestCase("$$10$$",                 '$', "",       10, "",     null,     "$$10$$")]
        [TestCase("$scheme$10$",            '$', "scheme", 10, "",     null,     "$scheme$10$$")]
        [TestCase("$scheme$10$salt",        '$', "scheme", 10, "salt", null,     "$scheme$10$salt$")]
        [TestCase("$scheme$10$salt$",       '$', "scheme", 10, "salt", null,     "$scheme$10$salt$")]
        [TestCase("$scheme$10$salt$cipher", '$', "scheme", 10, "salt", "cipher", "$scheme$10$salt$cipher")]
        public void Constructor1_ValidParams_Sucess(string modularCryptFormatStr,
                                                    char   delim,
                                                    string resultScheme,
                                                    int    resultWorkFactor,
                                                    string resultSalt,
                                                    string resultCipher,
                                                    string resultToString)
        {
            var mc = new ModularCrypt(modularCryptFormatStr,
                                      delim);
            Assert.AreEqual(delim,            mc.Delim);
            Assert.AreEqual(resultScheme,     mc.Scheme);
            Assert.AreEqual(resultWorkFactor, mc.WorkFactor);
            Assert.AreEqual(resultSalt,       mc.Salt);
            Assert.AreEqual(resultCipher,     mc.Cipher);
            Assert.AreEqual(resultToString,   mc.ToString());
        }
        
        [TestCase('$', "",       10, "",     null,     null,     "$$10$$")]
        [TestCase('$', "scheme", 10, "",     null,     null,     "$scheme$10$$")]
        [TestCase('$', "scheme", 10, "salt", null,     null,     "$scheme$10$salt$")]
        [TestCase('$', "scheme", 10, "salt", "",       null,     "$scheme$10$salt$")]
        [TestCase('$', "scheme", 10, "salt", "cipher", "cipher", "$scheme$10$salt$cipher")]
        public void Constructor2_ValidParams_Sucess(char   delim,
                                                    string scheme,
                                                    int    workFactor,
                                                    string salt,
                                                    string cipher,
                                                    string resultCipher,
                                                    string resultToString)
        {
            var mc = new ModularCrypt(delim,
                                      scheme,
                                      workFactor,
                                      salt,
                                      cipher);
            Assert.AreEqual(delim,          mc.Delim);
            Assert.AreEqual(scheme,         mc.Scheme);
            Assert.AreEqual(workFactor,     mc.WorkFactor);
            Assert.AreEqual(salt,           mc.Salt);
            Assert.AreEqual(resultCipher,   mc.Cipher);
            Assert.AreEqual(resultToString, mc.ToString());
        }
    }
}