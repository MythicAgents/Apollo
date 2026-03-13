using System;
using System.Text;
using System.Collections.Generic;

namespace HttpxTransform
{
    /// <summary>
    /// Core transform functions for httpx profile message obfuscation
    /// Based on httpx/C2_Profiles/httpx/httpx/c2functions/transforms.go
    /// </summary>
    public static class Transforms
    {
        /// <summary>
        /// Base64 encode data
        /// </summary>
        public static byte[] Base64Encode(byte[] data)
        {
            return Encoding.UTF8.GetBytes(Convert.ToBase64String(data));
        }

        /// <summary>
        /// Base64 decode data
        /// </summary>
        public static byte[] Base64Decode(byte[] data)
        {
            try
            {
                return Convert.FromBase64String(Encoding.UTF8.GetString(data));
            }
            catch
            {
                return data; // Return original if decode fails
            }
        }

        /// <summary>
        /// Base64 URL encode data (URL-safe base64)
        /// </summary>
        public static byte[] Base64UrlEncode(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            base64 = base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return Encoding.UTF8.GetBytes(base64);
        }

        /// <summary>
        /// Base64 URL decode data
        /// </summary>
        public static byte[] Base64UrlDecode(byte[] data)
        {
            try
            {
                string base64 = Encoding.UTF8.GetString(data);
                base64 = base64.Replace('-', '+').Replace('_', '/');
                
                // Add padding if needed
                switch (base64.Length % 4)
                {
                    case 2: base64 += "=="; break;
                    case 3: base64 += "="; break;
                }
                
                return Convert.FromBase64String(base64);
            }
            catch
            {
                return data; // Return original if decode fails
            }
        }

        /// <summary>
        /// NetBIOS encode data (lowercase)
        /// Split each byte into two nibbles, add 0x61 ('a')
        /// </summary>
        public static byte[] NetBiosEncode(byte[] data)
        {
            byte[] output = new byte[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                byte right = (byte)((data[i] & 0x0F) + 0x61);
                byte left = (byte)(((data[i] & 0xF0) >> 4) + 0x61);
                output[i * 2] = left;
                output[i * 2 + 1] = right;
            }
            return output;
        }

        /// <summary>
        /// NetBIOS decode data (lowercase)
        /// </summary>
        public static byte[] NetBiosDecode(byte[] data)
        {
            if (data.Length % 2 != 0) return data; // Invalid length
            
            byte[] output = new byte[data.Length / 2];
            for (int i = 0; i < output.Length; i++)
            {
                byte left = (byte)((data[i * 2] - 0x61) << 4);
                byte right = (byte)(data[i * 2 + 1] - 0x61);
                output[i] = (byte)(left | right);
            }
            return output;
        }

        /// <summary>
        /// NetBIOS encode data (uppercase)
        /// Split each byte into two nibbles, add 0x41 ('A')
        /// </summary>
        public static byte[] NetBiosUEncode(byte[] data)
        {
            byte[] output = new byte[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                byte right = (byte)((data[i] & 0x0F) + 0x41);
                byte left = (byte)(((data[i] & 0xF0) >> 4) + 0x41);
                output[i * 2] = left;
                output[i * 2 + 1] = right;
            }
            return output;
        }

        /// <summary>
        /// NetBIOS decode data (uppercase)
        /// </summary>
        public static byte[] NetBiosUDecode(byte[] data)
        {
            if (data.Length % 2 != 0) return data; // Invalid length
            
            byte[] output = new byte[data.Length / 2];
            for (int i = 0; i < output.Length; i++)
            {
                byte left = (byte)((data[i * 2] - 0x41) << 4);
                byte right = (byte)(data[i * 2 + 1] - 0x41);
                output[i] = (byte)(left | right);
            }
            return output;
        }

        /// <summary>
        /// XOR transform data with key
        /// </summary>
        public static byte[] XorTransform(byte[] data, string key)
        {
            if (string.IsNullOrEmpty(key)) return data;
            
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] output = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i++)
            {
                output[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);
            }
            
            return output;
        }

        /// <summary>
        /// Prepend data with value
        /// </summary>
        public static byte[] PrependTransform(byte[] data, string value)
        {
            if (string.IsNullOrEmpty(value)) return data;
            
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            byte[] output = new byte[valueBytes.Length + data.Length];
            
            Array.Copy(valueBytes, 0, output, 0, valueBytes.Length);
            Array.Copy(data, 0, output, valueBytes.Length, data.Length);
            
            return output;
        }

        /// <summary>
        /// Strip prepended data
        /// </summary>
        public static byte[] StripPrepend(byte[] data, string value)
        {
            if (string.IsNullOrEmpty(value)) return data;
            
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            if (data.Length < valueBytes.Length) return data;
            
            // Check if data starts with the value
            for (int i = 0; i < valueBytes.Length; i++)
            {
                if (data[i] != valueBytes[i]) return data;
            }
            
            byte[] output = new byte[data.Length - valueBytes.Length];
            Array.Copy(data, valueBytes.Length, output, 0, output.Length);
            
            return output;
        }

        /// <summary>
        /// Append data with value
        /// </summary>
        public static byte[] AppendTransform(byte[] data, string value)
        {
            if (string.IsNullOrEmpty(value)) return data;
            
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            byte[] output = new byte[data.Length + valueBytes.Length];
            
            Array.Copy(data, 0, output, 0, data.Length);
            Array.Copy(valueBytes, 0, output, data.Length, valueBytes.Length);
            
            return output;
        }

        /// <summary>
        /// Strip appended data
        /// </summary>
        public static byte[] StripAppend(byte[] data, string value)
        {
            if (string.IsNullOrEmpty(value)) return data;
            
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            if (data.Length < valueBytes.Length) return data;
            
            // Check if data ends with the value
            for (int i = 0; i < valueBytes.Length; i++)
            {
                if (data[data.Length - valueBytes.Length + i] != valueBytes[i]) return data;
            }
            
            byte[] output = new byte[data.Length - valueBytes.Length];
            Array.Copy(data, 0, output, 0, output.Length);
            
            return output;
        }
    }
}
