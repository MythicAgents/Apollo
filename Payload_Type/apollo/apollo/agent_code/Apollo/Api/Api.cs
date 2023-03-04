using ApolloInterop.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using ApolloInterop.Classes;
using PlaintextCryptography;
using PSKCryptography;
using ApolloInterop.Serializers;
using System.IO.Pipes;
using ApolloInterop.Classes.Api;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Core;
using DinvokeResolver = DInvokeResolver.DInvokeResolver;
using SimpleResolver;
namespace Apollo.Api
{
    public class Api : IApi
    {
        private IWin32ApiResolver _win32ApiResolver;
        public Api()
        {
            _win32ApiResolver = new GetProcResolver();
        }
        

        public string NewUUID()
        {
            return Guid.NewGuid().ToString();
        }

        public RSAKeyGenerator NewRSAKeyPair(int szKey)
        {
            return new Cryptography.RSA.RSAKeyPair(szKey);
        }

        public ICryptographySerializer NewEncryptedJsonSerializer(string uuid, Type cryptoType, string key = "")
        {
            if (string.IsNullOrEmpty(key))
            {
                Cryptography.RSA.RSAKeyPair keys = new Cryptography.RSA.RSAKeyPair(4096);
                key = keys.PrivateKey;
            }

            //string aesKey = "ACstCeIXHEqdn/QM3YsAX24yfRUX6JBtOdhkAwnfQrw=";
            //string uuid = "9f006dd8-7036-455b-99ed-d0b5f19ba921";

            EncryptedJsonSerializer result;

            if (cryptoType == typeof(PlaintextCryptographyProvider))
            {
                PlaintextCryptographyProvider plain = new PlaintextCryptographyProvider(uuid, key);
                result = new EncryptedJsonSerializer(plain);
            } else if (cryptoType == typeof(PSKCryptographyProvider))
            {
                PSKCryptographyProvider psk = new PSKCryptographyProvider(uuid, key);
                result = new EncryptedJsonSerializer(psk);
            }
            else
            {
                throw new ArgumentException($"Unsupported cryptography type: {cryptoType.Name}");
            }
            return result;
        }

        public T GetLibraryFunction<T>(Library library, string functionName, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            return _win32ApiResolver.GetLibraryFunction<T>(library, functionName, canLoadFromDisk, resolveForwards);
        }

        public T GetLibraryFunction<T>(Library library, short ordinal, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            return _win32ApiResolver.GetLibraryFunction<T>(library, ordinal, canLoadFromDisk, resolveForwards);
        }

        public T GetLibraryFunction<T>(Library library, string functionHash, long key, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            return _win32ApiResolver.GetLibraryFunction<T>(library, functionHash, key, canLoadFromDisk, resolveForwards);
        }
    }
}
