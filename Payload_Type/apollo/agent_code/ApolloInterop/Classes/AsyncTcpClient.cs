using ApolloInterop.Constants;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Net.Sockets;

namespace ApolloInterop.Classes
{
    public class AsyncTcpClient
    {
        private readonly TcpClient _client;
        private readonly ITcpClientCallback _callback;
        private readonly string _host;
        private readonly int _port;
        public AsyncTcpClient(string host, int port, ITcpClientCallback callback)
        {
            _client = new TcpClient();
            _callback = callback;
            _host = host;
            _port = port;
        }

        public bool Connect()
        {
            try
            {
                _client.Connect(_host, _port);
                // Client times out, so fail.
            }
            catch { return false; }
            // we set pipe to be message transactions ; don't think we need to for tcp
            IPCData pd = new IPCData()
            {
                Client = _client,
                State = null,
                Data = new byte[IPC.RECV_SIZE],
            };

            _callback.OnAsyncConnect(_client, out pd.State);
            BeginRead(pd);
            return true;
        }

        public void BeginRead(IPCData pd)
        {
            bool isConnected = pd.Client.Connected;
            if (isConnected)
            {
                try
                {
                    pd.Client.GetStream().BeginRead(pd.Data, 0, pd.Data.Length, OnAsyncMessageReceived, pd);
                }
                catch (Exception ex)
                {
                    isConnected = false;
                }
            }

            if (!isConnected)
            {
                pd.Client.Close();
                _callback.OnAsyncDisconnect(pd.Client, pd.State);
            }
        }

        private void OnAsyncMessageReceived(IAsyncResult result)
        {
            // read from client until complete
            IPCData pd = (IPCData)result.AsyncState;
            Int32 bytesRead = pd.Client.GetStream().EndRead(result);
            if (bytesRead > 0)
            {
                pd.DataLength = bytesRead;
                _callback.OnAsyncMessageReceived(pd.Client, pd, pd.State);
            }
            BeginRead(pd);
        }
    }
}
