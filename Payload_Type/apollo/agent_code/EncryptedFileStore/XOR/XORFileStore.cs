using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace EncryptedFileStore.XOR
{
    public class XORFileStore : EncryptedFileStore
    {
        private byte[] _key = new byte[]
        {
            66,
            105,
            114,
            100,
            115,
            65,
            114,
            101,
            110,
            116,
            82,
            101,
            97,
            108,
        };
        
        public XORFileStore(IAgent agent) : base(agent)
        { }

        private byte[] XOR(byte[] input)
        {
            int j = 0;
            for (int i = 0; i < input.Length; i++, j++)
            {
                if (j == _key.Length)
                {
                    j = 0;
                }
                input[i] = (byte)(input[i] ^ _key[j]);
            }

            return input;
        }
        
        public override string GetScript()
        {
            return Encoding.UTF8.GetString(XOR(_currentScript));
        }

        public override void SetScript(string script)
        {
            SetScript(XOR(Encoding.UTF8.GetBytes(script)));
        }

        public override void SetScript(byte[] script)
        {
            _currentScript = XOR(script);
        }

        public override bool TryAddOrUpdate(string keyName, byte[] data)
        {
            return _fileStore.TryAdd(keyName, XOR(data));
        }

        public override bool TryGetValue(string keyName, out byte[] data)
        {
            if (_fileStore.TryGetValue(keyName, out data))
            {
                data = XOR(data);
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}