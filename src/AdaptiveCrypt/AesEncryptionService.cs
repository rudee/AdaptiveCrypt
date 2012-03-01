using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AdaptiveCrypt
{
    public class AesEncryptionService : IEncryptionService
    {
        public AesEncryptionService(string key,
                                    int    saltLength,
                                    int    workfactor)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException(@"key must be non-null and not empty or white-space.",
                                            "key");
            }

            if (saltLength < 0)
            {
                throw new ArgumentOutOfRangeException("saltLength",
                                                      saltLength,
                                                      @"saltLength must be greater than 0.");
            }

            if (workfactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workfactor)
            {
                throw new ArgumentOutOfRangeException("workfactor",
                                                      workfactor,
                                                      string.Format("workfactor must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            _key        = key;
            _saltLength = saltLength;
            _workfactor = workfactor;
        }

        public int SaltLength
        {
            get { return _saltLength; }
        }

        public int Workfactor
        {
            get { return _workfactor; }
        }

        public string Encrypt(string str,
                              string salt,
                              int    workFactor)
        {
            if (str == null)
            {
                throw new ArgumentNullException("str",
                                                "str cannot be null");
            }

            if (salt == null)
            {
                throw new ArgumentNullException("salt",
                                                "salt cannot be null");
            }

            if (workFactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workFactor)
            {
                throw new ArgumentOutOfRangeException("workFactor",
                                                      workFactor,
                                                      string.Format("workFactor value must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            using (var aes = new AesCryptoServiceProvider())
            {
                InitAesKeyAndIv(aes,
                                salt,
                                workFactor);

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(str);
                    }

                    byte[] encrypted = ms.ToArray();
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        public string Decrypt(string cipher,
                              string salt,
                              int    workFactor)
        {
            if (cipher == null)
            {
                throw new ArgumentNullException("cipher",
                                                "cipher cannot be null");
            }

            if (salt == null)
            {
                throw new ArgumentNullException("salt",
                                                "salt cannot be null");
            }

            if (workFactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workFactor)
            {
                throw new ArgumentOutOfRangeException("workFactor",
                                                      workFactor,
                                                      string.Format("workFactor value must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            using (var aes = new AesCryptoServiceProvider())
            {
                InitAesKeyAndIv(aes,
                                salt,
                                workFactor);

                ICryptoTransform decryptor = aes.CreateDecryptor();

                using (var ms = new MemoryStream(Convert.FromBase64String(cipher)))
                {
                    try
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        using (var sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                    catch
                    {
                        return null;
                    }
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
                                     string             salt,
                                     int                workFactor)
        {
            byte[] saltAsBytes = Encoding.UTF8.GetBytes(salt);
            int    iterations  = 1 << workFactor;

            // The size of the salt used to create Rfc2898DeriveBytes must be at least 8 bytes.
            if (saltAsBytes.Length < 8)
            {
                // Increase the size and pad with the 0x00 byte value.
                Array.Resize(ref saltAsBytes, 8);
            }

            var db = new Rfc2898DeriveBytes(_key,
                                            saltAsBytes,
                                            iterations);

            // KeySize and BlockSize values are in bits, divide by 8 to get size in bytes
            // Note: the next 2 statements are meant to be computationally intensive depending on
            // the value of the iterations variable.
            aes.Key = db.GetBytes(aes.KeySize / 8);
            aes.IV  = db.GetBytes(aes.BlockSize / 8);
        }

        private readonly string _key;
        private readonly int    _saltLength;
        private readonly int    _workfactor;

        private const int MIN_VALID_WORK_FACTOR = 0;
        private const int MAX_VALID_WORK_FACTOR = 30;
    }
}