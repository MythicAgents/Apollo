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
using Apollo.Api.DInvoke;
using System.Runtime.InteropServices;

namespace Apollo.Api
{
    public class Api : IApi
    {
        public Api()
        {
        }

        public NamedPipeServerStream CreateNamedPipeServer(
            string pipeName,
            bool allowNetworkLogon = false,
            PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte)
        {
            return IO.Pipes.CreateAsyncNamedPipeServer(pipeName, allowNetworkLogon, transmissionMode);
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

        public Delegate GetLibraryFunction(Library library, string functionName, Type del, bool canLoadFromDisk = true)
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionName, canLoadFromDisk);
            return Marshal.GetDelegateForFunctionPointer(fn, del);
        }

        public Delegate GetLibraryFunction(Library library, short ordinal, Type del, bool canLoadFromDisk = true)
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), ordinal, canLoadFromDisk);
            return Marshal.GetDelegateForFunctionPointer(fn, del);
        }

        public Delegate GetLibraryFunction(Library library, string functionHash, long key, Type del, bool canLoadFromDisk = true)
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionHash, key, canLoadFromDisk);
            return Marshal.GetDelegateForFunctionPointer(fn, del);
        }
    }
}
