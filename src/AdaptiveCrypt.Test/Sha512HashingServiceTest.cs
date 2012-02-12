using System;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class Sha512HashingServiceTest
    {
        [SetUp]
        public void SetUp()
        {
        }

        [TearDown]
        public void TearDown()
        {
        }

        [Test]
        public void Constructor_ValidParams_Sucess([Values("key")]
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
    }
}