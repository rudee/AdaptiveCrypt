using System;
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

        [Test]
        public void Constructor_ValidParams_Instantiated([Values("key")]
                                                         string key,

                                                         [Values(0, 1, 10)]
                                                         int saltLength,

                                                         [Values(0, 1, 10)]
                                                         int workFactor)
        {
            var hs = new AesEncryptionService(key,
                                              saltLength,
                                              workFactor);
            Assert.AreEqual(saltLength, hs.SaltLength);
            Assert.AreEqual(workFactor, hs.Workfactor);
        }

        [TestCase(null, 10, 10)]
        [TestCase("",   10, 10)]
        [TestCase(" ",  10, 10)]
        [TestCase("\t", 10, 10)]
        public void Constructor_InvalidParams_ArgumentExceptionThrown(string key,
                                                                      int    saltLength,
                                                                      int    workFactor)
        {
            Assert.Throws<ArgumentException>(() => new AesEncryptionService(key,
                                                                            saltLength,
                                                                            workFactor));
        }

        [TestCase("key", -1, 10)]
        [TestCase("key", 10, -1)]
        [TestCase("key", 10, 31)]
        public void Constructor_InvalidParams_ArgumentOutOfRangeExceptionThrown(string key,
                                                                                int    saltLength,
                                                                                int    workFactor)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new AesEncryptionService(key,
                                                                                      saltLength,
                                                                                      workFactor));
        }

        [Test]
        public void Encrypt_ValidParams_Success([Values("key")]
                                                string key,

                                                [Values(0, 1, 10)]
                                                int workFactor,

                                                [Values("", " ", "\t", "str")]
                                                string str,

                                                [Values("", "salt")]
                                                string salt)
        {
            var es = new AesEncryptionService(key,
                                              salt.Length,
                                              workFactor);

            string cipher = es.Encrypt(str,
                                       salt,
                                       workFactor);

            Assert.IsNotNullOrEmpty(cipher);
            Assert.AreNotEqual(cipher, str);
            Assert.AreNotEqual(cipher, key);
            Assert.AreNotEqual(cipher, salt);
        }

        [TestCase("key", 8, 0,  null,  "")]
        [TestCase("key", 8, 0,  null,  "salt")]
        [TestCase("key", 8, 0,  "",    null)]
        [TestCase("key", 8, 0,  "str", null)]
        [TestCase("key", 8, 1,  null,  "")]
        [TestCase("key", 8, 1,  null,  "salt")]
        [TestCase("key", 8, 1,  "",    null)]
        [TestCase("key", 8, 1,  "str", null)]
        [TestCase("key", 8, 10, null,  "")]
        [TestCase("key", 8, 10, null,  "salt")]
        [TestCase("key", 8, 10, "",    null)]
        [TestCase("key", 8, 10, "str", null)]
        public void Encrypt_InvalidParams_ArgumentNullExceptionThrown(string key,
                                                                      int    saltLength,
                                                                      int    workFactor,
                                                                      string str,
                                                                      string salt)
        {
            var es = new AesEncryptionService(key,
                                              saltLength,
                                              workFactor);

            Assert.Throws<ArgumentNullException>(() => es.Encrypt(str,
                                                                  salt,
                                                                  workFactor));
        }

        [TestCase("key", 8, 0, -1, "str", "salt")]
        [TestCase("key", 8, 0, 31, "str", "salt")]
        public void Encrypt_InvalidParams_ArgumentOutOfRangeExceptionThrown(string key,
                                                                            int    saltLength,
                                                                            int    workFactor1,
                                                                            int    workFactor2,
                                                                            string str,
                                                                            string salt)
        {
            var es = new AesEncryptionService(key,
                                              saltLength,
                                              workFactor1);

            Assert.Throws<ArgumentOutOfRangeException>(() => es.Encrypt(str,
                                                                        salt,
                                                                        workFactor2));
        }

        [Test]
        public void Decrypt_ValidParams_Success([Values("key")]
                                                string key,

                                                [Values(0, 1, 10)]
                                                int workFactor,

                                                [Values("", " ", "\t", "str")]
                                                string str,

                                                [Values("", "salt")]
                                                string salt)
        {
            var es = new AesEncryptionService(key,
                                              salt.Length,
                                              workFactor);

            string cipher = es.Encrypt(str,
                                       salt,
                                       workFactor);

            string val = es.Decrypt(cipher,
                                    salt,
                                    workFactor);

            Assert.AreNotEqual(cipher, val);
        }
    }
}