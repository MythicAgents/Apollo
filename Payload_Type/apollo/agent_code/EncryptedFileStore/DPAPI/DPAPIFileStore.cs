using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace EncryptedFileStore.DPAPI
{
    public class DPAPIFileStore : EncryptedFileStore
    {
        private byte[] _additionalEntropy = System.Guid.NewGuid().ToByteArray();
        
        public DPAPIFileStore(IAgent agent) : base(agent)
        { }

        private byte[] Encrypt(byte[] Buffer)
        {
            return ProtectedData.Protect(Buffer, _additionalEntropy, DataProtectionScope.CurrentUser);
        }
        
        private byte[] Decrypt(byte[] Buffer)
        {
            return ProtectedData.Unprotect(Buffer, _additionalEntropy, DataProtectionScope.CurrentUser);
        }
        
        public override string GetScript()
        {
            return Encoding.UTF8.GetString(
                Decrypt(
                    _currentScript));
        }

        public override void SetScript(string script)
        {
            SetScript(Encoding.UTF8.GetBytes(script));
        }

        public override void SetScript(byte[] script)
        {
            _currentScript = Encrypt(script);
        }

        public override bool TryAddOrUpdate(string keyName, byte[] data)
        {
            return _fileStore.TryAdd(keyName, Encrypt(data));
        }

        public override bool TryGetValue(string keyName, out byte[] data)
        {
            data = null;
            if (_fileStore.TryGetValue(keyName, out data))
            {
                data = Decrypt(data);
                return true;
            }
            return false;
        }
    }
}