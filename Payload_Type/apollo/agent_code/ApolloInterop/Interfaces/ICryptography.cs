using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface ICryptography
    {
        string Encrypt(string plaintext);
        string Decrypt(string encrypted);
        bool UpdateUUID(string uuid);
        bool UpdateKey(string key);

        string GetUUID();
    }
}
