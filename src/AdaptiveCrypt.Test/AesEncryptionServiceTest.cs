﻿using System;
using System.Text;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class AesEncryptionServiceTest
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

        [TestCase("key")]
        [TestCase("")]
        public void Constructor_ValidParams_Success(string keyAsString)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyAsString);
            var    es  = new AesEncryptionService(key);
        }

        [Test]
        public void Encrypt_ValidParams_Success([Values(" ", "unencrypted")]
                                                string unencryptedAsString,

                                                [Values(0, 1, 10)]
                                                int workFactor,

                                                [Values("", " ", "salt")]
                                                string saltAsString)
        {
            byte[] unencrypted = Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = Encoding.UTF8.GetBytes(saltAsString);

            byte[] key1       = Encoding.UTF8.GetBytes("key1");
            byte[] key2       = Encoding.UTF8.GetBytes("key2");
            var    es1        = new AesEncryptionService(key1);
            var    es2        = new AesEncryptionService(key2);
            byte[] encrypted1 = es1.Encrypt(unencrypted, workFactor, salt);
            byte[] encrypted2 = es2.Encrypt(unencrypted, workFactor, salt);

            Assert.IsNotNull(encrypted1);
            Assert.IsNotNull(encrypted2);
            Assert.IsNotEmpty(encrypted1);
            Assert.IsNotEmpty(encrypted2);
            Assert.AreNotEqual(encrypted1, unencrypted);
            Assert.AreNotEqual(encrypted2, unencrypted);
            Assert.AreNotEqual(encrypted1, encrypted2);
        }

        [TestCase(null,          1, "")]
        [TestCase(null,          1, "salt")]
        [TestCase(" ",           1, null)]
        [TestCase("unencrypted", 1, null)]
        public void Encrypt_InvalidParams_ArgumentNullExceptionThrown(string unencryptedAsString,
                                                                      int    workFactor,
                                                                      string saltAsString)
        {
            byte[] unencrypted = unencryptedAsString == null ? null : Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = saltAsString        == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key = Encoding.UTF8.GetBytes("key");
            var    es  = new AesEncryptionService(key);

            Assert.Throws<ArgumentNullException>(() => es.Encrypt(unencrypted, workFactor, salt));
        }

        [TestCase("",            -1,  "")]
        [TestCase("unencrypted", -1,  "")]
        [TestCase("",            -1,  "salt")]
        [TestCase("unencrypted", -1,  "salt")]
        [TestCase("",            31,  "")]
        [TestCase("unencrypted", 31,  "")]
        [TestCase("",            31,  "salt")]
        [TestCase("unencrypted", 31,  "salt")]
        [TestCase("unencrypted", -50, "salt")]
        [TestCase("unencrypted", 50,  "salt")]
        public void Encrypt_InvalidParams_ArgumentOutOfRangeExceptionThrown(string unencryptedAsString,
                                                                            int    workFactor,
                                                                            string saltAsString)
        {
            byte[] unencrypted = unencryptedAsString == null ? null : Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = saltAsString        == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key = Encoding.UTF8.GetBytes("key");
            var    es  = new AesEncryptionService(key);

            Assert.Throws<ArgumentOutOfRangeException>(() => es.Encrypt(unencrypted, workFactor, salt));
        }

        [Test]
        public void Decrypt_ValidParams_Success([Values(" ", "unencrypted")]
                                                string unencryptedAsString,

                                                [Values(0, 1, 10)]
                                                int workFactor,

                                                [Values("", " ", "salt")]
                                                string saltAsString)
        {
            byte[] unencrypted = Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = Encoding.UTF8.GetBytes(saltAsString);

            byte[] key1       = Encoding.UTF8.GetBytes("key1");
            byte[] key2       = Encoding.UTF8.GetBytes("key2");
            var    es1        = new AesEncryptionService(key1);
            var    es2        = new AesEncryptionService(key2);
            byte[] encrypted1 = es1.Encrypt(unencrypted, workFactor, salt);
            byte[] encrypted2 = es2.Encrypt(unencrypted, workFactor, salt);
            byte[] decrypted1 = es1.Decrypt(encrypted1,  workFactor, salt);
            byte[] decrypted2 = es2.Decrypt(encrypted2,  workFactor, salt);

            Assert.IsNotNull(encrypted1);
            Assert.IsNotNull(encrypted2);
            Assert.IsNotEmpty(encrypted1);
            Assert.IsNotEmpty(encrypted2);
            Assert.AreNotEqual(encrypted1, encrypted2);
            Assert.AreEqual(decrypted1, decrypted2);
            Assert.AreEqual(unencrypted, decrypted1);
            Assert.AreEqual(unencrypted, decrypted2);
        }
    }
}