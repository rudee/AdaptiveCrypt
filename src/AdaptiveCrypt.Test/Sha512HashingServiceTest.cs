using System;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class Sha512HashingServiceTest
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
            var hs = new Sha512HashingService(key,
                                              saltLength,
                                              workFactor);
            Assert.AreEqual(saltLength, hs.SaltLength);
            Assert.AreEqual(workFactor, hs.WorkFactor);
        }

        [TestCase(null, 10, 10)]
        [TestCase("",   10, 10)]
        [TestCase(" ",  10, 10)]
        [TestCase("\t", 10, 10)]
        public void Constructor_InvalidParams_ArgumentExceptionThrown(string key,
                                                                      int    saltLength,
                                                                      int    workFactor)
        {
            Assert.Throws<ArgumentException>(() => new Sha512HashingService(key,
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
            Assert.Throws<ArgumentOutOfRangeException>(() => new Sha512HashingService(key,
                                                                                      saltLength,
                                                                                      workFactor));
        }

        [Test]
        public void Hash_ValidParams_Success([Values("key")]
                                             string key,

                                             [Values(0, 1, 10)]
                                             int workFactor,

                                             [Values("", "str")]
                                             string str,

                                             [Values("", "salt")]
                                             string salt)
        {
            var hs = new Sha512HashingService(key,
                                              salt.Length,
                                              workFactor);

            string hash = hs.Hash(str,
                                  salt,
                                  workFactor);

            Assert.IsNotNullOrEmpty(hash);
            Assert.AreNotEqual(hash, str);
            Assert.AreNotEqual(hash, key);
            Assert.AreNotEqual(hash, salt);
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
        public void Hash_InvalidParams_ArgumentNullExceptionThrown(string key,
                                                                   int    saltLength,
                                                                   int    workFactor,
                                                                   string str,
                                                                   string salt)
        {
            var hs = new Sha512HashingService(key,
                                              saltLength,
                                              workFactor);

            Assert.Throws<ArgumentNullException>(() => hs.Hash(str,
                                                               salt,
                                                               workFactor));
        }

        [TestCase("key", 8, 0, -1, "str", "salt")]
        [TestCase("key", 8, 0, 31, "str", "salt")]
        public void Hash_InvalidParams_ArgumentOutOfRangeExceptionThrown(string key,
                                                                         int    saltLength,
                                                                         int    workFactor1,
                                                                         int    workFactor2,
                                                                         string str,
                                                                         string salt)
        {
            var hs = new Sha512HashingService(key,
                                              saltLength,
                                              workFactor1);

            Assert.Throws<ArgumentOutOfRangeException>(() => hs.Hash(str,
                                                                     salt,
                                                                     workFactor2));
        }
    }
}