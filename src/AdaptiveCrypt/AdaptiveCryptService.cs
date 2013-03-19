using System;
using System.Collections.Generic;
using System.Linq;

namespace AdaptiveCrypt
{
    public class AdaptiveCryptService
    {
        public AdaptiveCryptService(string             defaultHashingIdentifier,
                                    int?               defaultHashingWorkFactor,
                                    int?               defaultHashingSaltLength,
                                    IHashingService    defaultHashingService,
                                    string             defaultEncryptionIdentifier,
                                    int?               defaultEncryptionWorkFactor,
                                    int?               defaultEncryptionSaltLength,
                                    IEncryptionService defaultEncryptionService)
            : this(defaultHashingIdentifier,
                   defaultHashingWorkFactor,
                   defaultHashingSaltLength,
                   defaultHashingService,
                   defaultEncryptionIdentifier,
                   defaultEncryptionWorkFactor,
                   defaultEncryptionSaltLength,
                   defaultEncryptionService,
                   null)
        {
        }

        public AdaptiveCryptService(string             defaultHashingIdentifier,
                                    int?               defaultHashingWorkFactor,
                                    int?               defaultHashingSaltLength,
                                    IHashingService    defaultHashingService,
                                    string             defaultEncryptionIdentifier,
                                    int?               defaultEncryptionWorkFactor,
                                    int?               defaultEncryptionSaltLength,
                                    IEncryptionService defaultEncryptionService,
                                    char?              modularCryptDelim)
        {
            _hashingServices    = new Dictionary<string, IHashingService>();
            _encryptionServices = new Dictionary<string, IEncryptionService>();

            defaultHashingIdentifier    = string.IsNullOrWhiteSpace(defaultHashingIdentifier)    ? null : defaultHashingIdentifier.Trim();
            defaultEncryptionIdentifier = string.IsNullOrWhiteSpace(defaultEncryptionIdentifier) ? null : defaultEncryptionIdentifier.Trim();

            if (defaultHashingIdentifier != null
                && defaultHashingWorkFactor != null
                && defaultHashingSaltLength != null
                && defaultHashingService != null)
            {
                _defaultHashingIdentifier = defaultHashingIdentifier;
                _defaultHashingWorkFactor = defaultHashingWorkFactor.Value;
                _defaultHashingSaltLength = defaultHashingSaltLength.Value;
                _hashingServices.Add(defaultHashingIdentifier, defaultHashingService);
            }

            if (defaultEncryptionIdentifier != null
                && defaultEncryptionWorkFactor != null
                && defaultEncryptionSaltLength != null
                && defaultEncryptionService != null)
            {
                _defaultEncryptionIdentifier = defaultEncryptionIdentifier;
                _defaultEncryptionWorkFactor = defaultEncryptionWorkFactor.Value;
                _defaultEncryptionSaltLength = defaultEncryptionSaltLength.Value;
                _encryptionServices.Add(defaultEncryptionIdentifier, defaultEncryptionService);
            }

            if (!_hashingServices.Any() && !_encryptionServices.Any())
            {
                throw new ArgumentException("Must specify a default Hashing Service or a default Encryption Service.");
            }

            _modularCryptDelim = modularCryptDelim ?? DEFAULT_MODULAR_CRYPT_DELIM;
        }

        public void AddHashingService(string          hashingIdentifier,
                                      IHashingService hashingService)
        {
            hashingIdentifier = string.IsNullOrWhiteSpace(hashingIdentifier) ? null : hashingIdentifier.Trim();

            if (hashingIdentifier == null)
            {
                throw new ArgumentNullException("hashingIdentifier", "Cannot be null or empty");
            }

            if (hashingService == null)
            {
                throw new ArgumentNullException("hashingService", "Cannot be null");
            }

            _hashingServices.Add(hashingIdentifier, hashingService);
        }

        public void AddEncryptionService(string             encryptionIdentifier,
                                         IEncryptionService encryptionService)
        {
            encryptionIdentifier = string.IsNullOrWhiteSpace(encryptionIdentifier) ? null : encryptionIdentifier.Trim();

            if (encryptionIdentifier == null)
            {
                throw new ArgumentNullException("encryptionIdentifier", "Cannot be null or empty");
            }

            if (encryptionService == null)
            {
                throw new ArgumentNullException("encryptionService", "Cannot be null");
            }

            _encryptionServices.Add(encryptionIdentifier, encryptionService);
        }

        public ModularCrypt Hash(byte[] data)
        {
            return Hash(data, GenerateModularCryptForHashing());
        }

        public ModularCrypt Hash(byte[]       data,
                                 ModularCrypt modularCrypt)
        {
            IHashingService hashingService;
            try
            {
                hashingService = _hashingServices[modularCrypt.Identifier];
            }
            catch (KeyNotFoundException)
            {
                throw new NotSupportedException("No IHashingService with the identifier " + modularCrypt.Identifier + " configured.");
            }

            byte[] hash = hashingService.Hash(data,
                                              modularCrypt.WorkFactor,
                                              modularCrypt.Salt);

            return new ModularCrypt(_modularCryptDelim,
                                    modularCrypt.Identifier,
                                    modularCrypt.WorkFactor,
                                    modularCrypt.Salt,
                                    hash);
        }

        public ModularCrypt Encrypt(byte[] unencrypted)
        {
            return Encrypt(unencrypted, GenerateModularCryptForEncryption());
        }

        public ModularCrypt Encrypt(byte[]       unencrypted,
                                    ModularCrypt modularCrypt)
        {
            IEncryptionService encryptionService;
            try
            {
                encryptionService = _encryptionServices[modularCrypt.Identifier];
            }
            catch (KeyNotFoundException)
            {
                throw new NotSupportedException("No IEncryptionService with the identifier " + modularCrypt.Identifier + " configured.");
            }

            byte[] encrypted = encryptionService.Encrypt(unencrypted,
                                                         modularCrypt.WorkFactor,
                                                         modularCrypt.Salt);

            return new ModularCrypt(_modularCryptDelim,
                                    modularCrypt.Identifier,
                                    modularCrypt.WorkFactor,
                                    modularCrypt.Salt,
                                    encrypted);
        }

        public byte[] Decrypt(ModularCrypt modularCrypt)
        {
            IEncryptionService encryptionService;
            try
            {
                encryptionService = _encryptionServices[modularCrypt.Identifier];
            }
            catch (KeyNotFoundException)
            {
                throw new NotSupportedException("No IEncryptionService with the identifier " + modularCrypt.Identifier + " configured.");
            }

            return encryptionService.Decrypt(modularCrypt.Cipher,
                                             modularCrypt.WorkFactor,
                                             modularCrypt.Salt);
        }

        private ModularCrypt GenerateModularCryptForHashing()
        {
            return new ModularCrypt(_modularCryptDelim,
                                    _defaultHashingIdentifier,
                                    _defaultHashingWorkFactor,
                                    GenerateSalt(_defaultHashingSaltLength),
                                    null);
        }

        private ModularCrypt GenerateModularCryptForEncryption()
        {
            return new ModularCrypt(_modularCryptDelim,
                                    _defaultEncryptionIdentifier,
                                    _defaultEncryptionWorkFactor,
                                    GenerateSalt(_defaultEncryptionSaltLength),
                                    null);
        }

        private byte[] GenerateSalt(int saltLengthInBytes)
        {
            var salt = new byte[saltLengthInBytes];
            s_random.NextBytes(salt);
            return salt;
        }

        private string                                  _defaultHashingIdentifier;
        private int                                     _defaultHashingSaltLength;
        private int                                     _defaultHashingWorkFactor;
        private string                                  _defaultEncryptionIdentifier;
        private int                                     _defaultEncryptionWorkFactor;
        private int                                     _defaultEncryptionSaltLength;
        private char                                    _modularCryptDelim;
        private IDictionary<string, IHashingService>    _hashingServices;
        private IDictionary<string, IEncryptionService> _encryptionServices;
        private static readonly Random s_random = new Random();
        private const char DEFAULT_MODULAR_CRYPT_DELIM = '$';
    }
}