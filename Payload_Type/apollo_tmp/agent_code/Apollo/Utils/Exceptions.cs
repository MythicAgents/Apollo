using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Utils
{

    namespace ErrorUtils 
    {
        public enum SocksError : uint
        {
            SuccessReply = 0,
            ServerFailure,
            RuleFailure,
            NetworkUnreachable,
            HostUnreachable,
            ConnectionRefused,
            TtlExpired,
            CommandNotSupported,
            AddrTypeNotSupported,
            // These are custom
            InvalidDatagram,
            Disconnected
        }

        public class SocksException : Exception
        {
            public SocksError ErrorCode { get; private set; }
            public SocksException(SocksError err)
            {
                ErrorCode = err;
            }

            public SocksException(string message, SocksError err) : base(message)
            {
                ErrorCode = err;
            }
            public SocksException(string message, SocksError err, Exception inner) : base(message, inner)
            {
                ErrorCode = err;
            }
        }
    }
}
