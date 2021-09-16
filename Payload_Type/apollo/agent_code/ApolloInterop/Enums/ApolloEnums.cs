using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Enums
{
    namespace ApolloEnums
    {
        public enum MessageDirection
        {
            ToMythic = 0,
            FromMythic = 1
        }

        public enum MessageType
        {
            C2ProfileData = 0,
            Credential,
            RemovedFileInformation,
            FileInformation,
            FileBrowser,
            EdgeNode,
            SocksDatagram,
            Artifact,
            TaskStatus,
            TaskResponse,
            DownloadRegistrationMessage,
            DownloadProgressMessage,
            Task,
            DelegateMessage,
            TaskingMessage,
            EKEHandshakeMessage,
            EKEHandshakeResponse,
            CheckinMessage,
            UploadMessage,
            MessageResponse,
        }
    }
}
