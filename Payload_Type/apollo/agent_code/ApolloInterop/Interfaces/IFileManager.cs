using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IFileManager
    {
        void ProcessResponse(UploadMessage resp);

        bool GetFile(string taskID, string fileID, out byte[] fileBytes);
    }
}
