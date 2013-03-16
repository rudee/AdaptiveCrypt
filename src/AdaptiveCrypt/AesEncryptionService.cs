using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdaptiveCrypt
{
    /// <summary>
    /// Performs symmetric encryption and decryption with variable key, salt length and workFactor using the System.Security.Cryptography.AesCryptoServiceProvider class.
    /// </summary>
    public class AesEncryptionService : IEncryptionService
    {
        public AesEncryptionService(byte[] key)
        {
            if (key == null)
            {
                key = new byte[] { };
            }

            _key = key;
        }

        public byte[] Encrypt(byte[] unencrypted,
                              byte[] salt,
                              int    workFactor)
        {
            if (unencrypted == null)
            {
                throw new ArgumentNullException("unencrypted", "Cannot be null");
            }

            salt = salt ?? new byte[] { };

            if (workFactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workFactor)
            {
                throw new ArgumentOutOfRangeException("workFactor",
                                                      workFactor,
                                                      string.Format("Value must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            using (var aes = new AesCryptoServiceProvider())
            {
                InitAesKeyAndIv(aes, salt, workFactor);

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(unencrypted, 0, unencrypted.Length);
                    return ms.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] encrypted,
                              byte[] salt,
                              int    workFactor)
        {
            if (encrypted == null)
            {
                throw new ArgumentNullException("encrypted", "Cannot be null");
            }

            salt = salt ?? new byte[] { };

            if (workFactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workFactor)
            {
                throw new ArgumentOutOfRangeException("workFactor",
                                                      workFactor,
                                                      string.Format("workFactor value must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            using (var encryptedMemoryStream = new MemoryStream(encrypted))
            using (var aes = new AesCryptoServiceProvider())
            {
                InitAesKeyAndIv(aes, salt, workFactor);
                ICryptoTransform decryptor = aes.CreateDecryptor();

                using (var cs = new CryptoStream(encryptedMemoryStream, decryptor, CryptoStreamMode.Read))
                {
                    var unencryptedMemoryStream = new MemoryStream();

                    cs.CopyTo(unencryptedMemoryStream);

                    return unencryptedMemoryStream.ToArray();
                }
            }
        }

        /// <summary>
        /// Initialises the key and initialisation vector of the SymmetricAlgorithm instance.
        /// </summary>
        /// <param name="aes">The instance of SymmetricAlgorithm to initialise for.</param>
        /// <param name="salt">The salt string to be used to generate the key and key and initialisation.</param>
        /// <param name="workFactor">The work factor to use to determine the number of iterations.</param>
        private void InitAesKeyAndIv(SymmetricAlgorithm aes,
                                     byte[]             salt,
                                     int                workFactor)
        {
            int iterations = 1 << workFactor;

            // The size of the salt used to create Rfc2898DeriveBytes must be at least 8 bytes.
            if (salt.Length < 8)
            {
                // Increase the size and pad with the 0x00 byte value.
                Array.Resize(ref salt, 8);
            }

            var db = new Rfc2898DeriveBytes(_key,
                                            salt,
                                            iterations);

            // KeySize and BlockSize values are in bits, divide by 8 to get size in bytes
            // Note: the next 2 statements are meant to be computationally intensive depending on
            // the value of the iterations variable.
            aes.Key = db.GetBytes(aes.KeySize / 8);
            aes.IV  = db.GetBytes(aes.BlockSize / 8);
        }

        private readonly byte[] _key;

        private const int MIN_VALID_WORK_FACTOR = 0;
        private const int MAX_VALID_WORK_FACTOR = 30;
    }
}