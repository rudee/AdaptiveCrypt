namespace AdaptiveCrypt
{
    public interface IHashingService
    {
        int SaltLength { get; }

        int Workfactor { get; }

        string Hash(string str,
                    string salt,
                    int    workFactor);
    }
}