using ApolloInterop.Classes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using ApolloInterop.Classes.Api;

namespace ApolloInterop.Interfaces
{
    public interface IApi
    {
        Delegate GetLibraryFunction(Library library, string functionName, Type del, bool canLoadFromDisk = true);
        Delegate GetLibraryFunction(Library library, short ordinal, Type del, bool canLoadFromDisk = true);
        Delegate GetLibraryFunction(Library library, string functionHash, long key, Type del, bool canLoadFromDisk=true);

        string NewUUID();

        RSAKeyGenerator NewRSAKeyPair(int szKey);

        // Maybe other formats in the future?
        ICryptographySerializer NewEncryptedJsonSerializer(string uuid, Type cryptoType, string key = "");

        NamedPipeServerStream CreateNamedPipeServer(string pipeName, bool allowNetworkLogon = false, PipeTransmissionMode transmissionMode = PipeTransmissionMode.Byte);
    
    }
}
