using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ApolloInterop.Classes
{
    public abstract class RSAKeyGenerator
    {
        public string SessionId { get; private set; }
        public RSACryptoServiceProvider RSA { get; protected set; }
        public RSAKeyGenerator(int szKey)
        {
            SessionId = GenerateSessionId();
        }

        public RSAKeyGenerator(RSACryptoServiceProvider provider)
        {
            SessionId = GenerateSessionId();
            RSA = provider;
        }

        public virtual string GenerateSessionId()
        {
            Random random = new Random((int)DateTime.UtcNow.Ticks);
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, 20)
                  .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public abstract string ExportPublicKey();
        public abstract string ExportPrivateKey();
    }
}
