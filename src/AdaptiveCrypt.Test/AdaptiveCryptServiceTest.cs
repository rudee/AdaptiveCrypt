using System;
using System.Text;
using NUnit.Framework;

namespace AdaptiveCrypt.Test
{
    [TestFixture]
    class AdaptiveCryptServiceTest
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
        public void Hash([Values("", " ", "data")]
                         string dataAsString)
        {
            byte[] data = Encoding.UTF8.GetBytes(dataAsString);

            var acs = new AdaptiveCryptService("sha512", 10, 8, new Sha512HashingService(Encoding.UTF8.GetBytes("secrethashkey")),
                                               "aes",    10, 8, new AesEncryptionService(Encoding.UTF8.GetBytes("secretencryptionkey")));

            ModularCrypt mc1 = acs.Hash(data);
            ModularCrypt mc2 = acs.Hash(data);
            ModularCrypt mc3 = acs.Hash(data, mc1);
            ModularCrypt mc4 = acs.Hash(data, mc2);

            Assert.AreNotEqual(mc1, mc2);
            Assert.AreNotEqual(mc3, mc4);
            Assert.AreEqual(mc1, mc3);
            Assert.AreEqual(mc2, mc4);
            Assert.IsNotNullOrEmpty(mc1.ToString());
            Assert.IsNotNullOrEmpty(mc2.ToString());
            Assert.IsNotNullOrEmpty(mc3.ToString());
            Assert.IsNotNullOrEmpty(mc4.ToString());
            Assert.AreNotEqual(mc1.ToString(), mc2.ToString());
            Assert.AreNotEqual(mc3.ToString(), mc4.ToString());
            Assert.AreEqual(mc1.ToString(), mc3.ToString());
            Assert.AreEqual(mc2.ToString(), mc4.ToString());
        }

        [Test]
        public void Encrypt_Decrypt([Values(null, "", " ", "data")]
                                    string dataAsString)
        {
            byte[] data = dataAsString == null ? new byte[] {} : Encoding.UTF8.GetBytes(dataAsString);

            var acs = new AdaptiveCryptService("sha512", 10, 8, new Sha512HashingService(Encoding.UTF8.GetBytes("secrethashkey")),
                                               "aes",    10, 8, new AesEncryptionService(Encoding.UTF8.GetBytes("secretencryptionkey")));

            ModularCrypt mc1 = acs.Hash(data);
            ModularCrypt mc2 = acs.Hash(data);
            ModularCrypt mc3 = acs.Hash(data, mc1);
            ModularCrypt mc4 = acs.Hash(data, mc2);

            Assert.AreNotEqual(mc1, mc2);
            Assert.AreNotEqual(mc3, mc4);
            Assert.AreEqual(mc1, mc3);
            Assert.AreEqual(mc2, mc4);
            Assert.IsNotNullOrEmpty(mc1.ToString());
            Assert.IsNotNullOrEmpty(mc2.ToString());
            Assert.IsNotNullOrEmpty(mc3.ToString());
            Assert.IsNotNullOrEmpty(mc4.ToString());
            Assert.AreNotEqual(mc1.ToString(), mc2.ToString());
            Assert.AreNotEqual(mc3.ToString(), mc4.ToString());
            Assert.AreEqual(mc1.ToString(), mc3.ToString());
            Assert.AreEqual(mc2.ToString(), mc4.ToString());
        }

        [Test, Explicit]
        public void Sample()
        {
            var acs = new AdaptiveCryptService("sha1", 10, 8, new Sha512HashingService(Encoding.UTF8.GetBytes("secret-hash-key-1")),
                                               "aes1", 10, 8, new AesEncryptionService(Encoding.UTF8.GetBytes("secret-encryption-key-1")));

            // Hashing a password
            ModularCrypt hash = acs.Hash(Encoding.UTF8.GetBytes("password"));
            string hashAsString = hash.ToString(); // $sha1$10$base64-salt$base64-hash

            // Validating a password
            var prevHash = new ModularCrypt(hashAsString);
            ModularCrypt testHash = acs.Hash(Encoding.UTF8.GetBytes("password"), prevHash);
            bool isValidPassword = testHash == prevHash;

            // Encrypting an email
            ModularCrypt encrypted = acs.Encrypt(Encoding.UTF8.GetBytes("foobar@example.com"));
            string encryptedAsString = encrypted.ToString(); // $aes1$10$base64-salt$base64-cipher

            // Decrypting an email
            var prevEncrypt = new ModularCrypt(encryptedAsString);
            byte[] emailAsBytes = acs.Decrypt(prevEncrypt);
            string email = Encoding.UTF8.GetString(emailAsBytes); // foobar@example.com

            // Configure new settings for increased computation cost
            acs = new AdaptiveCryptService("sha2", 11, 8, new Sha512HashingService(Encoding.UTF8.GetBytes("secret-hash-key-2")),
                                           "aes2", 11, 8, new AesEncryptionService(Encoding.UTF8.GetBytes("secret-encryption-key-2")));
            // Add previous settings to support previous records
            acs.AddHashingService("sha1", new Sha512HashingService(Encoding.UTF8.GetBytes("secret-hash-key-1")));
            acs.AddEncryptionService("aes1", new AesEncryptionService(Encoding.UTF8.GetBytes("secret-encryption-key-1")));
            // Compute new hash for existing password (e.g. when user authenticates successfully)
            prevHash = new ModularCrypt(hashAsString);
            testHash = acs.Hash(Encoding.UTF8.GetBytes("password"), prevHash);
            if (testHash == prevHash)
            {
                // Authenticate success, compute new hash with increased computation costs
                ModularCrypt newHash = acs.Hash(Encoding.UTF8.GetBytes("password"));
                string newHashAsString = newHash.ToString(); // $sha2$11$base64-salt$base64-hash
            }
            // Re-encrypt an email
            prevEncrypt = new ModularCrypt(encryptedAsString);
            Console.WriteLine(encryptedAsString);
            Console.WriteLine(prevEncrypt);
            emailAsBytes = acs.Decrypt(prevEncrypt);
            ModularCrypt newEncrypted = acs.Encrypt(emailAsBytes);
            string newEncryptedAsString = encrypted.ToString(); // $aes2$11$base64-salt$base64-cipher
        }
    }
}