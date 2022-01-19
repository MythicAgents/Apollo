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
using ApolloInterop.Classes.Core;

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

        public T GetLibraryFunction<T>(Library library, string functionName, bool canLoadFromDisk = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionName, canLoadFromDisk);
            if (fn == IntPtr.Zero)
                throw new Exception($"Failed to get address of {functionName} ({library})");
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }

        public T GetLibraryFunction<T>(Library library, short ordinal, bool canLoadFromDisk = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), ordinal, canLoadFromDisk);
            if (fn == IntPtr.Zero)
                throw new Exception($"Failed to get address of function with ordinal {ordinal} ({library})");
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }

        public T GetLibraryFunction<T>(Library library, string functionHash, long key, bool canLoadFromDisk = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionHash, key, canLoadFromDisk);
            if (fn == IntPtr.Zero)
                throw new Exception($"Failed to get address of function hash {functionHash} ({library})");
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }
    }
}
