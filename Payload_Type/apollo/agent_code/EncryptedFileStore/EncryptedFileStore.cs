using ApolloInterop.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptedFileStore
{
    public abstract class EncryptedFileStore : IEncryptedFileStore
    {
        protected IAgent _agent;
        protected byte[] _currentScript = new byte[0];
        protected ConcurrentDictionary<string, byte[]> _fileStore = new ConcurrentDictionary<string, byte[]>();

        public EncryptedFileStore(IAgent agent)
        {
            _agent = agent;
        }

        public abstract string GetScript();

        public abstract void SetScript(string script);

        public abstract void SetScript(byte[] script);

        public abstract bool TryAddOrUpdate(string keyName, byte[] data);

        public abstract bool TryGetValue(string keyName, out byte[] data);
    }
}
