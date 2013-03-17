namespace AdaptiveCrypt
{
    /// <summary>
    /// Computes a hash with variable salt length and workFactor.
    /// </summary>
    public interface IHashingService
    {
        /// <summary>
        /// Creates a cryptographic hash.
        /// </summary>
        /// <param name="data">The value to hash</param>
        /// <param name="workFactor">The work factor to use to create the cryptographic hash</param>
        /// <param name="salt">The salt to use to create the cryptographic hash</param>
        /// <returns></returns>
        byte[] Hash(byte[] data,
                    int    workFactor,
                    byte[] salt);
    }
}