using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AdaptiveCrypt
{
    /// <summary>
    /// Computes a SHA512 hash with variable key, salt length and workFactor using the System.Security.Cryptography.HMACSHA512 class.
    /// </summary>
    public class Sha512HashingService : IHashingService
    {
        public Sha512HashingService(string key,
                                    int    saltLength,
                                    int    workFactor)
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

            if (workFactor < MIN_VALID_WORK_FACTOR || MAX_VALID_WORK_FACTOR < workFactor)
            {
                throw new ArgumentOutOfRangeException("workFactor",
                                                      workFactor,
                                                      string.Format("workFactor must be between {0} and {1} inclusive.",
                                                                    MIN_VALID_WORK_FACTOR,
                                                                    MAX_VALID_WORK_FACTOR));
            }

            _key        = key;
            _saltLength = saltLength;
            _workFactor = workFactor;
        }

        public int SaltLength
        {
            get { return _saltLength; }
        }

        public int WorkFactor
        {
            get { return _workFactor; }
        }

        public string Hash(string str,
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

            byte[] sha512Key = CreateHashKey(str,
                                             salt,
                                             workFactor);
            byte[] hashInput = Encoding.UTF8.GetBytes(str + salt + _key);
            var    sha512    = new HMACSHA512(sha512Key);
            byte[] hash      = sha512.ComputeHash(hashInput);

            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Creates the hash key to be used to construct a HMACSHA512 instance.
        /// </summary>
        /// <param name="password">The password used to create the hash key.</param>
        /// <param name="salt">The salt used to create the hash key.</param>
        /// <param name="workFactor">The work factor to use to determine the number of iterations.</param>
        /// <returns>A pseudo-random key bytes of size 64 bytes to be used to construct a HMACSHA512 instance.</returns>
        private byte[] CreateHashKey(string str,
                                     string salt,
                                     int    workFactor)
        {
            byte[] saltAsBytes = Encoding.UTF8.GetBytes(salt);
            int iterations = 1 << workFactor;

            // The size of the salt used to create Rfc2898DeriveBytes must be at least 8 bytes.
            if (saltAsBytes.Length < 8)
            {
                // Increase the size and pad with the 0x00 byte value.
                Array.Resize(ref saltAsBytes, 8);
            }

            var db = new Rfc2898DeriveBytes(str + salt + _key,
                                            saltAsBytes,
                                            iterations);

            // 64 bytes is the recommended size for the HMACSHA512 secret key
            // Note: this next statement is meant to be computationally intensive depending on the
            // value of the iterations variable.
            return db.GetBytes(64);
        }

        private readonly string _key;
        private readonly int    _saltLength;
        private readonly int    _workFactor;

        private const int MIN_VALID_WORK_FACTOR = 0;
        private const int MAX_VALID_WORK_FACTOR = 30;
    }
}