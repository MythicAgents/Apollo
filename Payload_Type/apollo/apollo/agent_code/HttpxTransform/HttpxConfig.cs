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

        [JsonProperty("put")]
        public VariationConfig Put { get; set; }

        [JsonProperty("delete")]
        public VariationConfig Delete { get; set; }

        [JsonProperty("patch")]
        public VariationConfig Patch { get; set; }

        [JsonProperty("options")]
        public VariationConfig Options { get; set; }

        [JsonProperty("head")]
        public VariationConfig Head { get; set; }

        public HttpxConfig()
        {
            Get = new VariationConfig();
            Post = new VariationConfig();
            Put = new VariationConfig();
            Delete = new VariationConfig();
            Patch = new VariationConfig();
            Options = new VariationConfig();
            Head = new VariationConfig();
        }

        /// <summary>
        /// Get variation configuration by HTTP method name (case-insensitive)
        /// </summary>
        public VariationConfig GetVariation(string method)
        {
            if (string.IsNullOrEmpty(method))
                return null;

            switch (method.ToLower())
            {
                case "get": return Get;
                case "post": return Post;
                case "put": return Put;
                case "delete": return Delete;
                case "patch": return Patch;
                case "options": return Options;
                case "head": return Head;
                default: return null;
            }
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
            
            // Validate all configured HTTP methods
            var variations = new Dictionary<string, VariationConfig>
            {
                { "GET", Get },
                { "POST", Post },
                { "PUT", Put },
                { "PATCH", Patch },
                { "DELETE", Delete },
                { "OPTIONS", Options },
                { "HEAD", Head }
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
                }
                
                // Validate client transforms
                foreach (var transform in variation.Client?.Transforms ?? new List<TransformConfig>())
                {
                    if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                        throw new ArgumentException($"Invalid {method} client transform action: {transform.Action}");
                }
                
                // Validate server transforms
                foreach (var transform in variation.Server?.Transforms ?? new List<TransformConfig>())
                {
                    if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                        throw new ArgumentException($"Invalid {method} server transform action: {transform.Action}");
                }
            }
        }
    }
}
