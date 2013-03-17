using System;
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
            byte[] unencrypted = unencryptedAsString == null ? null : Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = saltAsString        == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key       = Encoding.UTF8.GetBytes("key");
            var    es        = new AesEncryptionService(key);
            byte[] encrypted = es.Encrypt(unencrypted, workFactor, salt);

            Assert.IsNotNull(encrypted);
            Assert.AreNotEqual(encrypted, unencrypted);
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
            byte[] unencrypted = unencryptedAsString == null ? null : Encoding.UTF8.GetBytes(unencryptedAsString);
            byte[] salt        = saltAsString        == null ? null : Encoding.UTF8.GetBytes(saltAsString);

            byte[] key       = Encoding.UTF8.GetBytes("key");
            var    es        = new AesEncryptionService(key);
            byte[] encrypted = es.Encrypt(unencrypted, workFactor, salt);
            byte[] decrypted = es.Decrypt(encrypted, workFactor, salt);

            Assert.AreNotEqual(unencrypted, decrypted);
        }
    }
}