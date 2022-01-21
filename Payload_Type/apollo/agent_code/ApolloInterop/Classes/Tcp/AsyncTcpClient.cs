using ApolloInterop.Constants;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Net;
using System.Net.Sockets;

namespace ApolloInterop.Classes
{
    public class AsyncTcpClient
    {
        private readonly TcpClient _client;
        private readonly string _host;
        private readonly int _port;
        private readonly IPAddress _addr = null;

        public event EventHandler<TcpMessageEventArgs> ConnectionEstablished;
        public event EventHandler<TcpMessageEventArgs> MessageReceived;
        public event EventHandler<TcpMessageEventArgs> Disconnect;

        public AsyncTcpClient(string host, int port)
        {
            _client = new TcpClient();
            _host = host;
            _port = port;
        }

        public AsyncTcpClient(IPAddress host, int port)
        {
            _client = new TcpClient();
            _addr = host;
            _port = port;
        }

        public bool Connect()
        {
            try
            {
                if (_addr == null)
                {
                    _client.Connect(_host, _port);
                } else
                {
                    _client.Connect(_addr, _port);
                }
                // Client times out, so fail.
            }
            catch { return false; }
            // we set pipe to be message transactions ; don't think we need to for tcp
            IPCData pd = new IPCData()
            {
                Client = _client,
                State = _client,
                NetworkStream = _client.GetStream(),
                Data = new byte[IPC.RECV_SIZE],
            };
            OnConnect(new TcpMessageEventArgs(_client, pd, _client));
            BeginRead(pd);
            return true;
        }

        private void OnConnect(TcpMessageEventArgs args)
        {
            if (ConnectionEstablished != null)
            {
                ConnectionEstablished(this, args);
            }
        }

        public void BeginRead(IPCData pd)
        {
            bool isConnected = pd.Client.Connected;
            if (isConnected)
            {
                try
                {
                    pd.NetworkStream.BeginRead(pd.Data, 0, pd.Data.Length, OnAsyncMessageReceived, pd);
                }
                catch (Exception ex)
                {
                    isConnected = false;
                }
            }

            if (!isConnected)
            {
                pd.Client.Close();
                OnDisconnect(new TcpMessageEventArgs(pd.Client, null, pd.State));
            }
        }

        private void OnDisconnect(TcpMessageEventArgs args)
        {
            if (Disconnect != null)
            {
                Disconnect(this, args);
            }
        }

        private void OnMessageReceived(TcpMessageEventArgs args)
        {
            if (MessageReceived != null)
            {
                MessageReceived(this, args);
            }
        }

        private void OnAsyncMessageReceived(IAsyncResult result)
        {
            // read from client until complete
            IPCData pd = (IPCData)result.AsyncState;
            try
            {
                Int32 bytesRead = pd.NetworkStream.EndRead(result);
                if (bytesRead > 0)
                {
                    pd.DataLength = bytesRead;
                    OnMessageReceived(new TcpMessageEventArgs(pd.Client, pd, pd.State));
                }
            } catch (Exception ex)
            {
                // Console.WriteLine($"Error in end read: {ex.Message}");
            }
            BeginRead(pd);
        }
    }
}
