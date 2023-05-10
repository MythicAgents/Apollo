using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Enums
{
    namespace ApolloEnums
    {
        public enum Socks5Error
        {
            SuccessReply,
            ServerFailure,
            RuleFailure,
            NetworkUnreachable,
            HostUnreachable,
            ConnectionRefused,
            TtlExpired,
            CommandNotSupported,
            AddrTypeNotSupported,
        }

        public enum SocksVersion
        {
            Socks5 = 5
        }

        public enum Socks5AuthError
        {
            Success = 0,
            Failure,
            NoAcceptable = 255,
        }

        public enum Socks5AuthType
        {
            NoAuth = 0,
            Version = 1, //????
            UsernamePassword = 2,
        }

        public enum Socks5AddressType
        {
            IPv4 = 1,
            FQDN = 3,
            IPv6 = 4
        }

        public enum Socks5Command
        {
            Connect = 1,
            Bind = 2,
            Associate = 3
        }

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
            DownloadMessage,
            FileBrowserACE,
            IPCCommandArguments,
            ProcessInformation,
            CommandInformation,
            ScreenshotInformation,
            KeylogInformation
        }
    }
}
