using ApolloInterop.Structs.MythicStructs;
using System.Threading;

namespace ApolloInterop.Interfaces
{
    public interface IFileManager
    {
        string[] GetPendingTransfers();
        void ProcessResponse(MythicTaskStatus resp);

        bool GetFile(CancellationToken ct, string taskID, string fileID, out byte[] fileBytes);

        bool PutFile(CancellationToken ct, string taskID, byte[] content, string originatingPath, out string mythicFileId, bool isScreenshot = false, string originatingHost = null);

        string GetScript();

        void SetScript(string script);

        void SetScript(byte[] script);

        bool AddFileToStore(string keyName, byte[] data);

        bool GetFileFromStore(string keyName, out byte[] data);
    }
}
