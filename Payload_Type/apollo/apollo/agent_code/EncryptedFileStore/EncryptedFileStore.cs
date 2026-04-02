using ApolloInterop.Interfaces;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;

namespace EncryptedFileStore
{
    public class EncryptedFileStore : IEncryptedFileStore
    {
        protected byte[] CurrentScript = new byte[0];
        protected readonly ConcurrentDictionary<string, byte[]> FileStore = new ConcurrentDictionary<string, byte[]>();
        private readonly ICryptographicRoutine[] _providers;
        public EncryptedFileStore(ICryptographicRoutine[] providers)
        {
            _providers = providers;
        }

        private byte[] EncryptData(byte[] data)
        {
            byte[] cipherText = data;

            for(int i = 0; i < _providers.Length; i++)
            {
                cipherText = _providers[i].Encrypt(cipherText);
            }
            return cipherText;
        }

        private byte[] DecryptData(byte[] data)
        {
            byte[] plainText = data;
            for(int i = _providers.Length - 1; i >= 0; i--)
            {
                plainText = _providers[i].Decrypt(plainText);
            }
            return plainText;
        }

        public string GetScript()
        {
            if (CurrentScript.Length == 0)
            {
                return "";
            }
            return Encoding.UTF8.GetString(DecryptData(CurrentScript));
        }

        public void SetScript(string script)
        {
            SetScript(Encoding.UTF8.GetBytes(script));
        }

        public void SetScript(byte[] script)
        {
            CurrentScript = EncryptData(script);
        }

        public bool TryAddOrUpdate(string keyName, byte[] data)
        {
            byte[] encData = EncryptData(data);
            if (FileStore.TryAdd(keyName, encData))
            {
                return true;
            }
            else
            {
                if (!FileStore.TryGetValue(keyName, out byte[] compData))
                {
                    return false;
                }
                return FileStore.TryUpdate(keyName, encData, compData);
            }
        }

        public bool TryGetValue(string keyName, out byte[] data)
        {
            if (FileStore.TryGetValue(keyName, out data))
            {
                data = DecryptData(data);
                return true;
            }

            return false;
        }

        public string[] ListFiles()
        {
            return FileStore.Keys.ToArray();
        }

        public bool RemoveFile(string keyName)
        {
            bool success = FileStore.TryRemove(keyName, out byte[] data);
            if (success)
            {
                if (keyName.EndsWith(".ps1"))
                {
                    // check if this is our current script, if so, remove it there too
                    if(data == CurrentScript)
                    {
                        CurrentScript = new byte[0];
                    }
                }
            }
            return success;
        }
    }
}
