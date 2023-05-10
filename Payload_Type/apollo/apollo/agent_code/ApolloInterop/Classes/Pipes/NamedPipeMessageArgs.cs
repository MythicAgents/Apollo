using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes
{
    public class NamedPipeMessageArgs : EventArgs
    {
        public PipeStream Pipe;
        public IPCData Data;
        public Object State;

        public NamedPipeMessageArgs(PipeStream pipe, IPCData? data, Object state)
        {
            Pipe = pipe;
            if (data != null)
                Data = (IPCData)data;
            State = state;
        }
    }
}
