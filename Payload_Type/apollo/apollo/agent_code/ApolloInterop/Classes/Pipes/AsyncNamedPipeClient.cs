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
        public event EventHandler<NamedPipeMessageArgs> MessageReceived;
        public event EventHandler<NamedPipeMessageArgs> ConnectionEstablished;
        public event EventHandler<NamedPipeMessageArgs> Disconnect;
        public AsyncNamedPipeClient(string host, string pipename)
        {
            _pipe = new NamedPipeClientStream(
                host,
                pipename,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough
            );
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
                State = _pipe,
                Data = new byte[IPC.RECV_SIZE],
            };
            OnConnectionEstablished(new NamedPipeMessageArgs(_pipe, pd, pd.State));
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
                OnDisconnect(new NamedPipeMessageArgs(pd.Pipe, null, pd.State));
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
                OnMessageReceived(new NamedPipeMessageArgs(pd.Pipe, pd, pd.State));
            } else
            {
                pd.Pipe.Close();
            }
            BeginRead(pd);
        }

        private void OnConnectionEstablished(NamedPipeMessageArgs args)
        {
            ConnectionEstablished?.Invoke(this, args);
        }

        private void OnMessageReceived(NamedPipeMessageArgs args)
        {
            MessageReceived?.Invoke(this, args);
        }

        private void OnDisconnect(NamedPipeMessageArgs args)
        {
            Disconnect?.Invoke(this, args);
        }
    }
}
