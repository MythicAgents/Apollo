using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptedFileStore.Plaintext
{
    public class PlaintextFileStore : EncryptedFileStore
    {
        public PlaintextFileStore(IAgent agent) : base(agent)
        { }

        public override string GetScript()
        {
            return Encoding.UTF8.GetString(_currentScript);
        }

        public override void SetScript(string script)
        {
            SetScript(Encoding.UTF8.GetBytes(script));
        }

        public override void SetScript(byte[] script)
        {
            _currentScript = script;
        }

        public override bool TryAddOrUpdate(string keyName, byte[] data)
        {
            return _fileStore.TryAdd(keyName, data);
        }

        public override bool TryGetValue(string keyName, out byte[] data)
        {

            return _fileStore.TryGetValue(keyName, out data);
        }
    }
}
