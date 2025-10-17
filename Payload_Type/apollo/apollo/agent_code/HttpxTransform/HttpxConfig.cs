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
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

        [JsonProperty("parameters")]
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();

        [JsonProperty("domain_specific_headers")]
        public Dictionary<string, Dictionary<string, string>> DomainSpecificHeaders { get; set; } = new Dictionary<string, Dictionary<string, string>>();

        [JsonProperty("message")]
        public MessageConfig Message { get; set; } = new MessageConfig();

        [JsonProperty("transforms")]
        public List<TransformConfig> Transforms { get; set; } = new List<TransformConfig>();
    }

    public class ServerConfig
    {
        [JsonProperty("headers")]
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();

        [JsonProperty("transforms")]
        public List<TransformConfig> Transforms { get; set; } = new List<TransformConfig>();
    }

    public class VariationConfig
    {
        [JsonProperty("verb")]
        public string Verb { get; set; }

        [JsonProperty("uris")]
        public List<string> Uris { get; set; } = new List<string>();

        [JsonProperty("client")]
        public ClientConfig Client { get; set; } = new ClientConfig();

        [JsonProperty("server")]
        public ServerConfig Server { get; set; } = new ServerConfig();
    }

    public class HttpxConfig
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("get")]
        public VariationConfig Get { get; set; } = new VariationConfig();

        [JsonProperty("post")]
        public VariationConfig Post { get; set; } = new VariationConfig();

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

            if (Get?.Uris == null || Get.Uris.Count == 0)
                throw new ArgumentException("GET URIs are required");

            if (Post?.Uris == null || Post.Uris.Count == 0)
                throw new ArgumentException("POST URIs are required");

            // Validate message locations
            var validLocations = new[] { "cookie", "query", "header", "body", "" };
            
            if (!Array.Exists(validLocations, loc => loc == Get?.Client?.Message?.Location))
                throw new ArgumentException("Invalid GET message location");

            if (!Array.Exists(validLocations, loc => loc == Post?.Client?.Message?.Location))
                throw new ArgumentException("Invalid POST message location");

            // Validate transform actions
            var validActions = new[] { "base64", "base64url", "netbios", "netbiosu", "xor", "prepend", "append" };
            
            foreach (var transform in Get?.Client?.Transforms ?? new List<TransformConfig>())
            {
                if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                    throw new ArgumentException($"Invalid GET client transform action: {transform.Action}");
            }

            foreach (var transform in Get?.Server?.Transforms ?? new List<TransformConfig>())
            {
                if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                    throw new ArgumentException($"Invalid GET server transform action: {transform.Action}");
            }

            foreach (var transform in Post?.Client?.Transforms ?? new List<TransformConfig>())
            {
                if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                    throw new ArgumentException($"Invalid POST client transform action: {transform.Action}");
            }

            foreach (var transform in Post?.Server?.Transforms ?? new List<TransformConfig>())
            {
                if (!Array.Exists(validActions, action => action == transform.Action?.ToLower()))
                    throw new ArgumentException($"Invalid POST server transform action: {transform.Action}");
            }
        }
    }
}
