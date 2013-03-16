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
        public Sha512HashingService(byte[] key)
        {
            if (key == null)
            {
                key = new byte[] { };
            }

            _key = key;
        }

        public byte[] Hash(byte[] data,
                           byte[] salt,
                           int    workFactor)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data", "Cannot be null");
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

            byte[] sha512Key = CreateHashKey(_key,
                                             salt,
                                             workFactor,
                                             KEY_SIZE);
            var    sha512    = new HMACSHA512(sha512Key);

            return sha512.ComputeHash(data);
        }

        /// <summary>
        /// Creates the hash key to be used to construct a HMACSHA512 instance.
        /// </summary>
        /// <param name="key">The value used to create the hash key.</param>
        /// <param name="salt">The salt used to create the hash key.</param>
        /// <param name="workFactor">The work factor to use to determine the number of iterations.</param>
        /// <param name="size">The size of the key in bytes to create.</param>
        /// <returns>A pseudo-random key to be used to construct a HMACSHA512 instance.</returns>
        private static byte[] CreateHashKey(byte[] key,
                                            byte[] salt,
                                            int    workFactor,
                                            int    size)
        {
            int iterations = 1 << workFactor;

            // The size of the salt used to create Rfc2898DeriveBytes must be at least 8 bytes.
            if (salt.Length < 8)
            {
                // Increase the size and pad with the 0x00 byte value.
                Array.Resize(ref salt, 8);
            }

            var db = new Rfc2898DeriveBytes(key,
                                            salt,
                                            iterations);

            // Note: this next statement is meant to be computationally intensive depending on the
            // value of the iterations variable.
            return db.GetBytes(size);
        }

        private readonly byte[] _key;

        private const int MIN_VALID_WORK_FACTOR = 0;
        private const int MAX_VALID_WORK_FACTOR = 30;
        private const int KEY_SIZE = 128; // 128 bytes is the recommended size for the HMACSHA512 secret key
    }
}