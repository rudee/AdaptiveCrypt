using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AdaptiveCrypt
{
    public struct ModularCrypt
    {
        public static bool operator ==(ModularCrypt mc1, ModularCrypt mc2)
        {
            return mc1.Equals(mc2);
        }

        public static bool operator !=(ModularCrypt mc1, ModularCrypt mc2)
        {
            return !(mc1.Equals(mc2));
        }

        public ModularCrypt(string modularCryptFormatStr)
        {
            if (string.IsNullOrWhiteSpace(modularCryptFormatStr))
            {
                throw new ArgumentException("Cannot be null, empty or whitespace.", "modularCryptFormatStr");
            }

            // First character is the delim character
            char delim = modularCryptFormatStr[0];
            if (INVALID_DELIM_ALPHABET.Contains(delim))
            {
                throw new ArgumentException("Delim character not allowed. '" + delim + "'");
            }

            // Split into ModularCrypt segments
            string[] mcSegments = modularCryptFormatStr.Split(new[] { delim }, StringSplitOptions.None);
            if (mcSegments.Length - 1 != 4)
            {
                throw new ArgumentException("Invalid ModularCryptFormat String: " + modularCryptFormatStr, "modularCryptFormatStr");
            }

            // WorkFactor part must be a non-negative integer
            int workFactor;
            if (!int.TryParse(mcSegments[FORMAT_WORKFACTOR_INDEX], out workFactor)
                || workFactor < 0)
            {
                throw new ArgumentException("WorkFactor segment must be a non-negative integer", "modularCryptFormatStr");
            }

            // Salt part must be a Base64 string
            byte[] salt;
            try
            {
                salt = Convert.FromBase64String(mcSegments[FORMAT_SALT_INDEX]);
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid Salt segment", "modularCryptFormatStr");
            }

            // Cipher part must be empty or a Base64 string
            byte[] cipher;
            try
            {
                cipher = mcSegments[FORMAT_CIPHER_INDEX] != string.Empty ? Convert.FromBase64String(mcSegments[FORMAT_CIPHER_INDEX]) : new byte[] { };
            }
            catch (IndexOutOfRangeException)
            {
                cipher = new byte[] { };
            }
            catch (ArgumentNullException)
            {
                throw new ArgumentException("Invalid Cipher component", "modularCryptFormatStr");
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid Cipher component", "modularCryptFormatStr");
            }

            _delim      = delim;
            _identifier = mcSegments[FORMAT_IDENTIFIER_INDEX];
            _workFactor = workFactor;
            _salt       = salt;
            _cipher     = cipher;
        }

        public ModularCrypt(char   delim,
                            string identifier,
                            int    workFactor,
                            byte[] salt,
                            byte[] cipher)
        {
            if (INVALID_DELIM_ALPHABET.Contains(delim))
            {
                throw new ArgumentException("Invalid delim character.", "modularCryptFormatStr");
            }

            if (identifier == null)
            {
                throw new ArgumentException("Cannot be null.", "identifier");
            }

            if (workFactor < 0)
            {
                throw new ArgumentException("Must be a non-negative integer.", "workFactor");
            }

            if (salt == null)
            {
                throw new ArgumentException("Cannot be null.", "salt");
            }

            if (cipher == null)
            {
                throw new ArgumentException("Cannot be null.", "cipher");
            }

            _delim      = delim;
            _identifier = identifier;
            _workFactor = workFactor;
            _salt       = salt;
            _cipher     = cipher;
        }

        public char   Delim      { get { return _delim;      } }
        public string Identifier { get { return _identifier; } }
        public int    WorkFactor { get { return _workFactor; } }
        public byte[] Salt       { get { return _salt;       } }
        public byte[] Cipher     { get { return _cipher;     } }

        public string SaltAsBase64String   { get { return _salt   == null ? null : Convert.ToBase64String(_salt);   } }
        public string CipherAsBase64String { get { return _cipher == null ? null : Convert.ToBase64String(_cipher); } }

        public override bool Equals(object value)
        {
            if (value == null || !(value is ModularCrypt))
            {
                return false;
            }

            var mc = (ModularCrypt)value;

            if (this.Delim != mc.Delim
                || this.Identifier != mc.Identifier
                || this.WorkFactor != mc.WorkFactor)
            {
                return false;
            }

            if (this.Salt != mc.Salt
                && ((this.Salt == null && mc.Salt != null)
                    || (this.Salt != null && mc.Salt == null)
                    || (this.Salt != null && mc.Salt != null && !this.Salt.SequenceEqual(mc.Salt))
                   )
               )
            {
                return false;
            }

            if (this.Cipher != mc.Cipher
                && ((this.Cipher == null && mc.Cipher != null)
                    || (this.Cipher != null && mc.Cipher == null)
                    || (this.Cipher != null && mc.Cipher != null && !this.Cipher.SequenceEqual(mc.Cipher))
                   )
               )
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            int hash = 17;

            hash = 17 * 23 * _delim.GetHashCode()
                      * 23 * _identifier.GetHashCode()
                      * 23 * _workFactor.GetHashCode()
                      * 23 * _salt.GetHashCode()
                      * 23 * _cipher.GetHashCode();

            return hash;
        }

        public override string ToString()
        {
            return string.Format(FORMAT,
                                 _delim,
                                 _identifier,
                                 _workFactor,
                                 SaltAsBase64String,
                                 CipherAsBase64String);
        }

        public bool Equals(ModularCrypt value)
        {
            return Equals((object)value);
        }

        private char   _delim;
        private string _identifier;
        private int    _workFactor;
        private byte[] _salt;
        private byte[] _cipher;

        private const string FORMAT                  = "{0}{1}{0}{2}{0}{3}{0}{4}";
        private const int    FORMAT_IDENTIFIER_INDEX = 1;
        private const int    FORMAT_WORKFACTOR_INDEX = 2;
        private const int    FORMAT_SALT_INDEX       = 3;
        private const int    FORMAT_CIPHER_INDEX     = 4;
        internal const string INVALID_DELIM_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="; // Delim character cannot be a character in the Base64 alphabet
    }
}