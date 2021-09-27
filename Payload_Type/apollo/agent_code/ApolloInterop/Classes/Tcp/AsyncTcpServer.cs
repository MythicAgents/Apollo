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
        private readonly ITcpClientCallback _callback;
        private readonly int _BUF_IN;
        private readonly int _BUF_OUT;
        private readonly int _port;
        private readonly TcpListener _server;
        private ConcurrentDictionary<TcpClient, IPCData> _connections = new ConcurrentDictionary<TcpClient, IPCData>();

        internal class ConcurrentIPCData
        {
            internal int CurrentCount;
            internal IPCData[] Data;
        }
        private ConcurrentDictionary<string, ConcurrentIPCData> _messageBag = new ConcurrentDictionary<string, ConcurrentIPCData>();


        private bool _running = true;

        public AsyncTcpServer(int port, ITcpClientCallback callback, int BUF_IN = Constants.IPC.RECV_SIZE, int BUF_OUT = Constants.IPC.SEND_SIZE)
        {
            _callback = callback;
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
                State = null,
                Data = new byte[_BUF_IN],
            };

            // Add to connection list
            if (_running && _connections.TryAdd(client, pd))
            {
                _callback.OnAsyncConnect(client, out pd.State);
                BeginRead(pd);
            }
            else
            {
                client.Close();
            }
        }

        private void BeginRead(IPCData pd)
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
                _connections.TryRemove(pd.Client, out IPCData _);
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
