using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AdaptiveCrypt
{
    public class ModularCrypt
    {
        public ModularCrypt(string modularCryptFormatStr,
                            char   delim)
        {
            if (string.IsNullOrWhiteSpace(modularCryptFormatStr))
            {
                throw new ArgumentException("Cannot be null, empty or whitespace.", "modularCryptFormatStr");
            }

            string[] mcParts = modularCryptFormatStr.Split(new [] { delim },
                                                           StringSplitOptions.None);

            if (mcParts.Length - 1 != 4)
            {
                throw new ArgumentException("Invalid ModularCryptFormat String: " + modularCryptFormatStr, "modularCryptFormatStr");
            }

            Delim  = delim;
            Scheme = mcParts[FORMAT_SCHEME_INDEX];

            try
            {
                WorkFactor = int.Parse(mcParts[FORMAT_WORKFACTOR_INDEX]);
            }
            catch (FormatException)
            {
                throw new ArgumentException("Invalid WorkFactor", "modularCryptFormatStr");
            }

            Salt = mcParts[FORMAT_SALT_INDEX];

            try
            {
                Cipher = mcParts[FORMAT_CIPHER_INDEX];
                if (Cipher == string.Empty)
                {
                    Cipher = null;
                }
            }
            catch (IndexOutOfRangeException)
            {
                Cipher = null;
            }
        }

        public ModularCrypt(char   delim,
                            string scheme,
                            int    workFactor,
                            string salt,
                            string cipher)
        {
            Delim = delim;

            if (scheme == null)
            {
                throw new ArgumentException("Cannot be null.", "scheme");
            }
            Scheme = scheme;

            WorkFactor = workFactor;

            Salt = salt;
            if (Salt == string.Empty)
            {
                Salt = null;
            }

            Cipher = cipher;
            if (Cipher == string.Empty)
            {
                Cipher = null;
            }
        }

        public char   Delim      { get; set; }
        public string Scheme     { get; set; }
        public int    WorkFactor { get; set; }
        public string Salt       { get; set; }
        public string Cipher     { get; set; }

        public override string ToString()
        {
            return string.Format(FORMAT,
                                 Delim,
                                 Scheme,
                                 WorkFactor,
                                 Salt,
                                 Cipher);
        }

        private const string FORMAT                  = "{0}{1}{0}{2}{0}{3}{0}{4}";
        private const int    FORMAT_SCHEME_INDEX     = 1;
        private const int    FORMAT_WORKFACTOR_INDEX = 2;
        private const int    FORMAT_SALT_INDEX       = 3;
        private const int    FORMAT_CIPHER_INDEX     = 4;
    }
}