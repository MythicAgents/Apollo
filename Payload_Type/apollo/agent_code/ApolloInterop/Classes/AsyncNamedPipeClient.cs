using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public class AsyncNamedPipeClient
    {
        private readonly NamedPipeClientStream _pipe;

        public AsyncNamedPipeClient(string host, string pipename)
        {
            _pipe = new NamedPipeClientStream(
                host,
                pipename,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough
            );
        }

        public PipeStream Connect(Int32 timeout)
        {
            _pipe.Connect(timeout);
            _pipe.ReadMode = PipeTransmissionMode.Message;
            return _pipe;
        }
    }
}
