using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace HttpxTransform
{
    /// <summary>
    /// Configuration classes for httpx malleable profiles
    /// Based on httpx/C2_Profiles/httpx/httpx/c2functions/builder.go structures
    /// </summary>
    public class TransformConfig
    {
        [JsonProperty("action")]
        public string Action { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }
    }

    public class MessageConfig
    {
        [JsonProperty("location")]
        public string Location { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }
    }

    public class ClientConfig
    {
        [JsonProperty("headers")]
        public Dictionary<string, string> Headers { get; set; }

        [JsonProperty("parameters")]
        public Dictionary<string, string> Parameters { get; set; }

        [JsonProperty("domain_specific_headers")]
        public Dictionary<string, Dictionary<string, string>> DomainSpecificHeaders { get; set; }

        [JsonProperty("message")]
        public MessageConfig Message { get; set; }

        [JsonProperty("transforms")]
        public List<TransformConfig> Transforms { get; set; }

        public ClientConfig()
        {
            Headers = new Dictionary<string, string>();
            Parameters = new Dictionary<string, string>();
            DomainSpecificHeaders = new Dictionary<string, Dictionary<string, string>>();
            Message = new MessageConfig();
            Transforms = new List<TransformConfig>();
        }
    }

    public class ServerConfig
    {
        [JsonProperty("headers")]
        public Dictionary<string, string> Headers { get; set; }

        [JsonProperty("transforms")]
        public List<TransformConfig> Transforms { get; set; }

        public ServerConfig()
        {
            Headers = new Dictionary<string, string>();
            Transforms = new List<TransformConfig>();
        }
    }

    public class VariationConfig
    {
        [JsonProperty("verb")]
        public string Verb { get; set; }

        [JsonProperty("uris")]
        public List<string> Uris { get; set; }

        [JsonProperty("client")]
        public ClientConfig Client { get; set; }

        [JsonProperty("server")]
        public ServerConfig Server { get; set; }

        public VariationConfig()
        {
            Uris = new List<string>();
            Client = new ClientConfig();
            Server = new ServerConfig();
        }
    }

    public class HttpxConfig
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("get")]
        public VariationConfig Get { get; set; }

        [JsonProperty("post")]
        public VariationConfig Post { get; set; }

        public HttpxConfig()
        {
            Get = new VariationConfig();
            Post = new VariationConfig();
        }

        /// <summary>
        /// Get variation configuration by HTTP method name (case-insensitive)
        /// Only supports GET and POST methods
        /// </summary>
        public VariationConfig GetVariation(string method)
        {
            if (string.IsNullOrEmpty(method))
                return null;

            switch (method.ToLower())
            {
                case "get": return Get;
                case "post": return Post;
                default: return null;
            }
        }

        /// <summary>
        /// Check if a variation is actually configured (has verb, URIs, or meaningful config)
        /// </summary>
        public bool IsVariationConfigured(VariationConfig variation)
        {
            if (variation == null)
                return false;

            return !string.IsNullOrEmpty(variation.Verb) ||
                   (variation.Uris != null && variation.Uris.Count > 0) ||
                   (variation.Client != null && (
                       (variation.Client.Headers != null && variation.Client.Headers.Count > 0) ||
                       (variation.Client.Parameters != null && variation.Client.Parameters.Count > 0) ||
                       (variation.Client.Transforms != null && variation.Client.Transforms.Count > 0) ||
                       (variation.Client.Message != null && !string.IsNullOrEmpty(variation.Client.Message.Location))
                   )) ||
                   (variation.Server != null && (
                       (variation.Server.Headers != null && variation.Server.Headers.Count > 0) ||
                       (variation.Server.Transforms != null && variation.Server.Transforms.Count > 0)
                   ));
        }

        /// <summary>
        /// Get a configured variation by HTTP method name, returns null if not configured
        /// </summary>
        public VariationConfig GetConfiguredVariation(string method)
        {
            var variation = GetVariation(method);
            return IsVariationConfigured(variation) ? variation : null;
        }

        /// <summary>
        /// Load configuration from JSON string
        /// </summary>
        public static HttpxConfig FromJson(string json)
        {
            try
            {
                return JsonConvert.DeserializeObject<HttpxConfig>(json);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Failed to parse httpx configuration: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Load configuration from embedded resource
        /// </summary>
        public static HttpxConfig FromResource(string resourceName)
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                using (var stream = assembly.GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                        throw new ArgumentException($"Resource '{resourceName}' not found");

                    using (var reader = new System.IO.StreamReader(stream))
                    {
                        string json = reader.ReadToEnd();
                        return FromJson(json);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Failed to load httpx configuration from resource '{resourceName}': {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Validate configuration
        /// </summary>
        public void Validate()
        {
            if (string.IsNullOrEmpty(Name))
                throw new ArgumentException("Configuration name is required");

            // At least GET or POST must be configured
            bool hasGet = Get?.Uris != null && Get.Uris.Count > 0;
            bool hasPost = Post?.Uris != null && Post.Uris.Count > 0;
            
            if (!hasGet && !hasPost)
                throw new ArgumentException("At least GET or POST URIs are required");

            // Validate message locations
            var validLocations = new[] { "cookie", "query", "header", "body", "" };
            
            // Validate transform actions
            var validActions = new[] { "base64", "base64url", "netbios", "netbiosu", "xor", "prepend", "append" };
            
            // Validate all configured HTTP methods (only GET and POST are supported)
            var variations = new Dictionary<string, VariationConfig>
            {
                { "GET", Get },
                { "POST", Post }
            };
            
            foreach (var kvp in variations)
            {
                var method = kvp.Key;
                var variation = kvp.Value;
                
                if (variation == null) continue; // Method not configured, skip validation
                
                // Check if method is actually configured (has verb set or has URIs)
                // If neither, it's just a default initialized object and should be skipped
                bool isConfigured = !string.IsNullOrEmpty(variation.Verb) || 
                                   (variation.Uris != null && variation.Uris.Count > 0) ||
                                   (variation.Client != null && (
                                       (variation.Client.Headers != null && variation.Client.Headers.Count > 0) ||
                                       (variation.Client.Parameters != null && variation.Client.Parameters.Count > 0) ||
                                       (variation.Client.Transforms != null && variation.Client.Transforms.Count > 0) ||
                                       (variation.Client.Message != null && !string.IsNullOrEmpty(variation.Client.Message.Location))
                                   )) ||
                                   (variation.Server != null && (
                                       (variation.Server.Headers != null && variation.Server.Headers.Count > 0) ||
                                       (variation.Server.Transforms != null && variation.Server.Transforms.Count > 0)
                                   ));
                
                if (!isConfigured) continue; // Method not actually configured, skip validation
                
                // Validate URIs
                if (variation.Uris == null || variation.Uris.Count == 0)
                    throw new ArgumentException($"{method} URIs are required if {method} method is configured");
                
                // Validate message location
                if (variation.Client?.Message != null)
                {
                    if (!Array.Exists(validLocations, loc => loc == variation.Client.Message.Location))
                        throw new ArgumentException($"Invalid {method} message location: {variation.Client.Message.Location}");
                    
                    // Message name is required when location is not "body" or empty string
                    string location = variation.Client.Message.Location?.ToLower() ?? "";
                    if (location != "body" && location != "")
                    {
                        if (string.IsNullOrEmpty(variation.Client.Message.Name))
                            throw new ArgumentException($"Missing name for {method} variation location '{variation.Client.Message.Location}'. Message name is required when location is 'cookie', 'query', or 'header'.");
                    }
                }
                
                // Validate client transforms
                foreach (var transform in variation.Client?.Transforms ?? new List<TransformConfig>())
                {
                    if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                        throw new ArgumentException($"Invalid {method} client transform action: {transform.Action}");
                    
                    // Prepend/append transforms are not allowed when message location is "query"
                    // The query parameter name is handled separately, and prepend/append would corrupt the data
                    // when the server extracts only the query value (without the parameter name)
                    string transformAction = transform.Action?.ToLower();
                    if (variation.Client?.Message != null && 
                        variation.Client.Message.Location?.ToLower() == "query" &&
                        (transformAction == "prepend" || transformAction == "append"))
                    {
                        throw new ArgumentException(
                            $"{method} client transforms cannot use '{transform.Action}' when message location is 'query'. " +
                            "Prepend/append transforms corrupt query parameter values because the server extracts only the parameter value " +
                            "(without the parameter name), causing transform mismatches. Use prepend/append only for 'body', 'header', or 'cookie' locations.");
                    }
                }
                
                // Validate server transforms
                foreach (var transform in variation.Server?.Transforms ?? new List<TransformConfig>())
                {
                    if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                        throw new ArgumentException($"Invalid {method} server transform action: {transform.Action}");
                }
                
                // Validate encoding consistency: client and server must use matching base64/base64url encoding
                // Find the last encoding transform in client transforms (base64 or base64url)
                string clientEncoding = null;
                if (variation.Client?.Transforms != null)
                {
                    foreach (var transform in variation.Client.Transforms)
                    {
                        string action = transform.Action?.ToLower();
                        if (action == "base64" || action == "base64url")
                        {
                            clientEncoding = action;
                        }
                    }
                }
                
                // Find the first encoding transform in server transforms (base64 or base64url)
                // Server transforms are applied in reverse order, so we check from the end
                string serverEncoding = null;
                if (variation.Server?.Transforms != null)
                {
                    // Check transforms in reverse order (as they're applied)
                    for (int i = variation.Server.Transforms.Count - 1; i >= 0; i--)
                    {
                        string action = variation.Server.Transforms[i].Action?.ToLower();
                        if (action == "base64" || action == "base64url")
                        {
                            serverEncoding = action;
                            break; // Found the first encoding transform (last in list, first applied)
                        }
                    }
                }
                
                // If both client and server have encoding transforms, they must match
                if (clientEncoding != null && serverEncoding != null && clientEncoding != serverEncoding)
                {
                    throw new ArgumentException($"{method} encoding mismatch: client uses {clientEncoding} but server uses {serverEncoding}. Client and server encoding transforms must match.");
                }
            }
        }
    }
}
