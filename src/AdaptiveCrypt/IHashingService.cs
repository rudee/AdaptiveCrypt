namespace AdaptiveCrypt
{
    /// <summary>
    /// Computes a hash with variable key, salt length and workFactor.
    /// </summary>
    public interface IHashingService
    {
        /// <summary>
        /// Gets the length in characters for salts to be used by this hashing service.
        /// </summary>
        int SaltLength { get; }

        /// <summary>
        /// Gets the work factor to be used by this hashing service.
        /// </summary>
        int WorkFactor { get; }

        /// <summary>
        /// Creates a cryptographic hash.
        /// </summary>
        /// <param name="str">The value to hash</param>
        /// <param name="salt">The salt to use to create the cryptographic hash</param>
        /// <param name="workFactor">The work factor to use to create the cryptographic hash</param>
        /// <returns></returns>
        string Hash(string str,
                    string salt,
                    int    workFactor);
    }
}