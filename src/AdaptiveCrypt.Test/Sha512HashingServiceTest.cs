using System;
using System.Text;
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

        [TestCase("key")]
        [TestCase("")]
        public void Constructor_ValidParams_Success(string keyAsString)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyAsString);
            var    hs  = new Sha512HashingService(key);
        }

        [Test]
        public void Hash_ValidParams_Success([Values("", " ", "data")]
                                             string dataAsString,

                                             [Values(0, 1, 10)]
                                             int workFactor,

                                             [Values("", " ", "salt")]
                                             string saltAsString)
        {
            byte[] data = dataAsString == null ? null : Encoding.UTF8.GetBytes(dataAsString);
            byte[] salt = saltAsString == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key  = Encoding.UTF8.GetBytes("key");
            var    hs   = new Sha512HashingService(key);
            byte[] hash = hs.Hash(data, workFactor, salt);

            Assert.IsNotNull(hash);
            Assert.AreNotEqual(hash, data);
        }

        [TestCase(null,   1, "")]
        [TestCase(null,   1, "salt")]
        [TestCase("",     1, null)]
        [TestCase("data", 1, null)]
        public void Hash_InvalidParams_ArgumentNullExceptionThrown(string dataAsString,
                                                                   int    workFactor,
                                                                   string saltAsString)
        {
            byte[] data = dataAsString == null ? null : Encoding.UTF8.GetBytes(dataAsString);
            byte[] salt = saltAsString == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key = Encoding.UTF8.GetBytes("key");
            var    hs  = new Sha512HashingService(key);

            Assert.Throws<ArgumentNullException>(() => hs.Hash(data, workFactor, salt));
        }

        [TestCase("",     -1,  "")]
        [TestCase("data", -1,  "")]
        [TestCase("",     -1,  "salt")]
        [TestCase("data", -1,  "salt")]
        [TestCase("",     31,  "")]
        [TestCase("data", 31,  "")]
        [TestCase("",     31,  "salt")]
        [TestCase("data", 31,  "salt")]
        [TestCase("data", -50, "salt")]
        [TestCase("data", 50,  "salt")]
        public void Hash_InvalidParams_ArgumentOutOfRangeExceptionThrown(string dataAsString,
                                                                         int    workFactor,
                                                                         string saltAsString)
        {
            byte[] data = dataAsString == null ? null : Encoding.UTF8.GetBytes(dataAsString);
            byte[] salt = saltAsString == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key = Encoding.UTF8.GetBytes("key");
            var    hs  = new Sha512HashingService(key);

            Assert.Throws<ArgumentOutOfRangeException>(() => hs.Hash(data, workFactor, salt));
        }
    }
}