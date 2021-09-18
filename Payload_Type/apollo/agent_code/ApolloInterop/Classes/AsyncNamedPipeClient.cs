using ApolloInterop.Constants;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
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
        private readonly INamedPipeCallback _callback;

        public AsyncNamedPipeClient(string host, string pipename, INamedPipeCallback callback)
        {
            _pipe = new NamedPipeClientStream(
                host,
                pipename,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough
            );
            _callback = callback;
        }

        public bool Connect(Int32 msTimeout)
        {
            try
            {
                _pipe.Connect(msTimeout);
                // Client times out, so fail.
            } catch { return false; }
            _pipe.ReadMode = PipeTransmissionMode.Message;
            IPCData pd = new IPCData()
            {
                Pipe = _pipe,
                State = null,
                Data = new byte[IPC.RECV_SIZE],
            };

            _callback.OnAsyncConnect(_pipe, out pd.State);
            BeginRead(pd);
            return true;
        }

        public void BeginRead(IPCData pd)
        {
            bool isConnected = pd.Pipe.IsConnected;
            if (isConnected)
            {
                try
                {
                    pd.Pipe.BeginRead(pd.Data, 0, pd.Data.Length, OnAsyncMessageReceived, pd);
                } catch (Exception ex)
                {
                    isConnected = false;
                }
            }

            if (!isConnected)
            {
                pd.Pipe.Close();
                _callback.OnAsyncDisconnect(pd.Pipe, pd.State);
            }
        }

        private void OnAsyncMessageReceived(IAsyncResult result)
        {
            // read from client until complete
            IPCData pd = (IPCData)result.AsyncState;
            Int32 bytesRead = pd.Pipe.EndRead(result);
            if (bytesRead > 0)
            {
                pd.DataLength = bytesRead;
                _callback.OnAsyncMessageReceived(pd.Pipe, pd, pd.State);
            }
            BeginRead(pd);
        }
    }
}
