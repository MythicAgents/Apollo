using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Security.Principal;
using System.Net;
using System.Net.Sockets;

namespace ApolloInterop.Classes
{
    public class AsyncTcpServer
    {
        private readonly int _BUF_IN;
        private readonly int _BUF_OUT;
        private readonly int _port;
        private readonly TcpListener _server;
        
        private ConcurrentDictionary<TcpClient, IPCData> _connections = new ConcurrentDictionary<TcpClient, IPCData>();

        public event EventHandler<TcpMessageEventArgs> ConnectionEstablished;
        public event EventHandler<TcpMessageEventArgs> MessageReceived;
        public event EventHandler<TcpMessageEventArgs> Disconnect;

        private void OnConnect(object sender, TcpMessageEventArgs args) => ConnectionEstablished?.Invoke(sender, args);
        private void OnMessageReceived(object sender, TcpMessageEventArgs args) => MessageReceived?.Invoke(sender, args);
        private void OnDisconnect(object sender, TcpMessageEventArgs args) => Disconnect?.Invoke(sender, args);

        private bool _running = true;

        public AsyncTcpServer(int port, int BUF_IN = Constants.IPC.RECV_SIZE, int BUF_OUT = Constants.IPC.SEND_SIZE)
        {
            _BUF_IN = BUF_IN;
            _BUF_OUT = BUF_OUT;
            _port = port;
            _server = new TcpListener(IPAddress.Any, port);
            _server.Start();
            _server.BeginAcceptTcpClient(OnClientConnected, _server);
        }

        public void Stop()
        {
            _running = false;
            foreach (var client in _connections.Keys)
            {
                client.Close();
            }
            while (true)
            {
                int count = _connections.Count;
                if (count == 0)
                    break;
                System.Threading.Thread.Sleep(5);
            }
        }

        private void OnClientConnected(IAsyncResult result)
        {
            // complete connection
            TcpListener server = (TcpListener)result.AsyncState;
            TcpClient client = server.EndAcceptTcpClient(result);

            // create client pipe structure
            IPCData pd = new IPCData()
            {
                Client = client,
                NetworkStream = client.GetStream(),
                State = null,
                Data = new byte[_BUF_IN],
            };

            // Add to connection list
            if (_running && _connections.TryAdd(client, pd))
            {
                _server.BeginAcceptTcpClient(OnClientConnected, _server);
                OnConnect(this, new TcpMessageEventArgs(client, null, this));
                BeginRead(pd);
            }
            else
            {
                client.Close();
            }
        }

        private void BeginRead(IPCData pd)
        {
            bool isConnected;
            try
            {
                isConnected = pd.Client.Connected;
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
            } catch { isConnected = false; }

            if (!isConnected)
            {
                pd.Client.Client?.Close();
                OnDisconnect(this, new TcpMessageEventArgs(pd.Client, null, pd.State));
                _connections.TryRemove(pd.Client, out IPCData _);
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
                    OnMessageReceived(this, new TcpMessageEventArgs(pd.Client, pd, pd.State));
                }
            } catch (Exception ex)
            {
                pd.Client.Close();
            }
            BeginRead(pd);
        }
    }
}
