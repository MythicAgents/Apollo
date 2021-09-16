using ApolloInterop.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;

namespace ApolloInterop.Interfaces
{
    public interface IApi
    {
        T GetFunction<T>(string library, string functionName);

        string NewUUID();

        RSAKeyGenerator NewRSAKeyPair(int szKey);

        // Maybe other formats in the future?
        ICryptographySerializer NewEncryptedJsonSerializer(string uuid, Type cryptoType, string key = "");

        NamedPipeServerStream CreateNamedPipeServer(string pipeName, bool allowNetworkLogon = false, PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte);
    }
}
