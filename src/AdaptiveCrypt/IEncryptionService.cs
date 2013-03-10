namespace AdaptiveCrypt
{
    /// <summary>
    /// Performs symmetric encryption and decryption with variable key, salt length and workFactor.
    /// </summary>
    public interface IEncryptionService
    {
        /// <summary>
        /// Gets the length in characters for salts to be used by this encryption service.
        /// </summary>
        int SaltLength { get; }

        /// <summary>
        /// Gets the work factor to be used by this encryption service.
        /// </summary>
        int WorkFactor { get; }

        /// <summary>
        /// Encrypts the given value.
        /// </summary>
        /// <param name="str">The value to encrypt</param>
        /// <param name="salt">The salt to use in the encryption</param>
        /// <param name="workFactor">The work factor to use in the encryption</param>
        /// <returns></returns>
        string Encrypt(string str,
                       string salt,
                       int    workFactor);

        /// <summary>
        /// Decrypts the given cipher.
        /// </summary>
        /// <param name="cipher">The value to decrypt</param>
        /// <param name="salt">The salt to use in the decryption</param>
        /// <param name="workFactor">The work factor to use in the decryption</param>
        /// <returns></returns>
        string Decrypt(string cipher,
                       string salt,
                       int    workFactor);
    }
}