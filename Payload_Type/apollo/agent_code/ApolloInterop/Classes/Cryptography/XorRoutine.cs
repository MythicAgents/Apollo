using ApolloInterop.Interfaces;

namespace ApolloInterop.Classes.Cryptography
{
    public class XorRoutine : ICryptographicRoutine
    {
        private byte[] _key;
        
        public XorRoutine(byte[] key = null)
        {
            if (key == null)
            {
                _key = System.Guid.NewGuid().ToByteArray();
            }
        }

        private byte[] Xor(byte[] input)
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
        
        public byte[] Encrypt(byte[] data)
        {
            return Xor(data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return Xor(data);
        }
    }
}