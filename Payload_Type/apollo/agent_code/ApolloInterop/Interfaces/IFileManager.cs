using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace ApolloInterop.Interfaces
{
    public interface IFileManager
    {
        void ProcessResponse(TaskStatus resp);

        bool GetFile(CancellationToken ct, string taskID, string fileID, out byte[] fileBytes);
    }
}
