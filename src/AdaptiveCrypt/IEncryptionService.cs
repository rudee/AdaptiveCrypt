namespace AdaptiveCrypt
{
    /// <summary>
    /// Performs symmetric encryption and decryption with variable salt length and workFactor.
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Encrypts the given value.
        /// </summary>
        /// <param name="unencrypted">The value to encrypt</param>
        /// <param name="workFactor">The work factor to use in the encryption</param>
        /// <param name="salt">The salt to use in the encryption</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] unencrypted,
                       int    workFactor,
                       byte[] salt);

        /// <summary>
        /// Decrypts the given cipher.
        /// </summary>
        /// <param name="encrypted">The value to decrypt</param>
        /// <param name="workFactor">The work factor to use in the decryption</param>
        /// <param name="salt">The salt to use in the decryption</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] encrypted,
                       int    workFactor,
                       byte[] salt);
    }
}