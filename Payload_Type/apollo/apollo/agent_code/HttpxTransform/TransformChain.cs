using System;
using System.Collections.Generic;
using System.Text;

namespace HttpxTransform
{
    /// <summary>
    /// Apply transform sequences for httpx profile message obfuscation
    /// </summary>
    public static class TransformChain
    {
        /// <summary>
        /// Apply client transforms to outgoing data
        /// </summary>
        public static byte[] ApplyClientTransforms(byte[] data, List<TransformConfig> transforms)
        {
            if (transforms == null || transforms.Count == 0) return data;

            byte[] result = data;
            
            // Apply transforms in order
            foreach (var transform in transforms)
            {
                result = ApplyTransform(result, transform.Action, transform.Value);
            }
            
            return result;
        }

        /// <summary>
        /// Apply server transforms to incoming data (reverse order)
        /// </summary>
        public static byte[] ApplyServerTransforms(byte[] data, List<TransformConfig> transforms)
        {
            if (transforms == null || transforms.Count == 0) return data;

            byte[] result = data;
            
            // Apply transforms in reverse order
            for (int i = transforms.Count - 1; i >= 0; i--)
            {
                var transform = transforms[i];
                result = ApplyReverseTransform(result, transform.Action, transform.Value);
            }
            
            return result;
        }

        /// <summary>
        /// Apply a single transform
        /// </summary>
        private static byte[] ApplyTransform(byte[] data, string action, string value)
        {
            if (string.IsNullOrEmpty(action)) return data;

            switch (action.ToLower())
            {
                case "base64":
                    return Transforms.Base64Encode(data);
                
                case "base64url":
                    return Transforms.Base64UrlEncode(data);
                
                case "netbios":
                    return Transforms.NetBiosEncode(data);
                
                case "netbiosu":
                    return Transforms.NetBiosUEncode(data);
                
                case "xor":
                    return Transforms.XorTransform(data, value);
                
                case "prepend":
                    return Transforms.PrependTransform(data, value);
                
                case "append":
                    return Transforms.AppendTransform(data, value);
                
                default:
                    return data; // Unknown transform, return original
            }
        }

        /// <summary>
        /// Apply a single reverse transform
        /// </summary>
        private static byte[] ApplyReverseTransform(byte[] data, string action, string value)
        {
            if (string.IsNullOrEmpty(action)) return data;

            switch (action.ToLower())
            {
                case "base64":
                    return Transforms.Base64Decode(data);
                
                case "base64url":
                    return Transforms.Base64UrlDecode(data);
                
                case "netbios":
                    return Transforms.NetBiosDecode(data);
                
                case "netbiosu":
                    return Transforms.NetBiosUDecode(data);
                
                case "xor":
                    return Transforms.XorTransform(data, value); // XOR is symmetric
                
                case "prepend":
                    return Transforms.StripPrepend(data, value);
                
                case "append":
                    return Transforms.StripAppend(data, value);
                
                default:
                    return data; // Unknown transform, return original
            }
        }

        /// <summary>
        /// Build HTTP headers string from dictionary
        /// </summary>
        public static string BuildHeaders(Dictionary<string, string> headers)
        {
            if (headers == null || headers.Count == 0) return "";

            var headerLines = new List<string>();
            foreach (var header in headers)
            {
                headerLines.Add($"{header.Key}: {header.Value}");
            }
            
            return string.Join("\r\n", headerLines) + "\r\n";
        }

        /// <summary>
        /// Build query parameters string
        /// </summary>
        public static string BuildQueryParameters(Dictionary<string, string> parameters)
        {
            if (parameters == null || parameters.Count == 0) return "";

            var paramPairs = new List<string>();
            foreach (var param in parameters)
            {
                paramPairs.Add($"{Uri.EscapeDataString(param.Key)}={Uri.EscapeDataString(param.Value)}");
            }
            
            return string.Join("&", paramPairs);
        }

        /// <summary>
        /// Build cookie string from headers
        /// </summary>
        public static string ExtractCookieValue(string cookieHeader, string cookieName)
        {
            if (string.IsNullOrEmpty(cookieHeader) || string.IsNullOrEmpty(cookieName))
                return "";

            var cookies = cookieHeader.Split(';');
            foreach (var cookie in cookies)
            {
                var trimmed = cookie.Trim();
                if (trimmed.StartsWith(cookieName + "="))
                {
                    return trimmed.Substring(cookieName.Length + 1);
                }
            }
            
            return "";
        }

        /// <summary>
        /// Extract header value from response headers
        /// </summary>
        public static string ExtractHeaderValue(string headers, string headerName)
        {
            if (string.IsNullOrEmpty(headers) || string.IsNullOrEmpty(headerName))
                return "";

            var lines = headers.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                if (line.StartsWith(headerName + ":", StringComparison.OrdinalIgnoreCase))
                {
                    return line.Substring(headerName.Length + 1).Trim();
                }
            }
            
            return "";
        }
    }
}
