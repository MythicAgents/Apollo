#define COMMAND_NAME_UPPER

#if DEBUG
#define NETSTAT
#endif

#if NETSTAT

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using ApolloInterop.Classes.Api;

namespace Tasks
{
    public class netstat : Tasking
    {
        [DataContract()]
        private struct NetstatEntry {
            [DataMember(Name = "local_address")] public string LocalAddress;
            [DataMember(Name = "remote_address")] public string RemoteAddress;
            [DataMember(Name = "local_port")] public int LocalPort;
            [DataMember(Name = "remote_port")] public int RemotePort;
            [DataMember(Name = "pid")] public uint Pid;
            [DataMember(Name = "state")] public string State;
            [DataMember(Name = "protocol")] public string Protocol;
            [DataMember(Name = "ip_version")] public int IpVersion;
        }

        [DataContract()]
        private struct NetstatParameters {
            [DataMember(Name = "tcp")] public bool Tcp;
            [DataMember(Name = "udp")] public bool Udp;
            [DataMember(Name = "established")] public bool Established;
            [DataMember(Name = "listen")] public bool Listen;
        }

        #region imports

        private delegate uint GetExtendedTcpTable(
            IntPtr tcpTable,
            ref int tcpTableLength,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tcpTableType,
            int reserved = 0);
        private static GetExtendedTcpTable _pGetExtendedTcpTable = null;

        private delegate uint GetExtendedUdpTable(
            IntPtr pTcpTable, 
            ref int dwOutBufLen, 
            bool sort, 
            int ipVersion,
            UDP_TABLE_CLASS tblClass, 
            uint reserved = 0);
        private static GetExtendedUdpTable _pGetExtendedUdpTable = null;
        
        #endregion
        
        #region typedefs
        
        #region Enums
        // https://msdn2.microsoft.com/en-us/library/aa366386.aspx
        private enum TCP_TABLE_CLASS 
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        #endregion
        
        #region structs

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private byte[] localAddr;
            private uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] localPort;
            private uint owningPid;

            public uint ProcessId => owningPid;
            
            private long LocalScopeId => localScopeId;

            public IPAddress LocalAddress => new IPAddress(localAddr, LocalScopeId);

            public ushort LocalPort => BitConverter.ToUInt16(localPort.Take(2).Reverse().ToArray(), 0);
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDP6TABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_UDP6ROW_OWNER_PID[] table;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_UDPROW_OWNER_PID[] table;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            private uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] localPort;
            private uint owningPid;

            public uint ProcessId => owningPid;

            public IPAddress LocalAddress => new IPAddress(localAddr);

            public ushort LocalPort => BitConverter.ToUInt16(new byte[2] { localPort[1], localPort[0] }, 0);
        }
        
        // https://stackoverflow.com/a/577660
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            private uint state;
            private uint localAddr;
            private byte localPort1;
            private byte localPort2;
            private byte localPort3;
            private byte localPort4;
            private uint remoteAddr;
            private byte remotePort1;
            private byte remotePort2;
            private byte remotePort3;
            private byte remotePort4;
            private uint owningPid;

            public uint ProcessId => owningPid;
            public IPAddress LocalAddress => new IPAddress(localAddr);

            public IPAddress RemoteAddress => new IPAddress(remoteAddr);

            public ushort LocalPort => BitConverter.ToUInt16(new byte[2] { localPort2, localPort1}, 0);

            public ushort RemotePort => BitConverter.ToUInt16(new byte[2] {remotePort2, remotePort1}, 0);

            public TcpState State => (TcpState)state;
        }
        
        // https://msdn2.microsoft.com/en-us/library/aa366921.aspx
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID 
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        // https://www.pinvoke.net/default.aspx/Structures/MIB_TCP6ROW_OWNER_PID.html
        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private byte[] localAddr;

            private uint localScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private byte[] remoteAddr;

            private uint remoteScopeId;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] remotePort;

            private uint state;
            private uint owningPid;
            
            public uint ProcessId => owningPid;

            private long LocalScopeId => localScopeId;

            public IPAddress LocalAddress => new IPAddress(localAddr, LocalScopeId);

            public ushort LocalPort => BitConverter.ToUInt16(localPort.Take(2).Reverse().ToArray(), 0);

            private long RemoteScopeId => remoteScopeId;

            public IPAddress RemoteAddress => new IPAddress(remoteAddr, RemoteScopeId);

            public ushort RemotePort => BitConverter.ToUInt16(remotePort.Take(2).Reverse().ToArray(), 0);

            public TcpState State => (TcpState)state;
        }

        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366905
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6TABLE_OWNER_PID 
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_TCP6ROW_OWNER_PID[] table;
        }

        #endregion

        #endregion
        
        public netstat(IAgent agent, MythicTask data) : base(agent, data)
        {
            if (_pGetExtendedTcpTable == null)
            {
                _pGetExtendedTcpTable = _agent.GetApi().GetLibraryFunction<GetExtendedTcpTable>(Library.IPHLPAPI, "GetExtendedTcpTable");
            }
            if (_pGetExtendedUdpTable == null)
            {
                _pGetExtendedUdpTable = _agent.GetApi().GetLibraryFunction<GetExtendedUdpTable>(Library.IPHLPAPI, "GetExtendedUdpTable");
            }
        }
        
        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public class IConnectionWrapper : IDisposable 
        {
             private const int AF_INET = 2;    // IP_v4 = System.Net.Sockets.AddressFamily.InterNetwork
             private const int AF_INET6 = 23;  // IP_v6 = System.Net.Sockets.AddressFamily.InterNetworkV6

            // Creates a new wrapper for the local machine
            public IConnectionWrapper() { }

            // Disposes of this wrapper
            public void Dispose() 
            {
                GC.SuppressFinalize(this);
            }

            public List<MIB_TCPROW_OWNER_PID> GetAllTCPv4Connections() 
            {
                return GetTCPConnections<MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID>(AF_INET);
            }

            public List<MIB_TCP6ROW_OWNER_PID> GetAllTCPv6Connections() 
            {
                return GetTCPConnections<MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID>(AF_INET6);
            }
      
            public List<MIB_UDPROW_OWNER_PID> GetAllUDPv4Connections()
            { 
                return GetUDPConnections<MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID>(AF_INET);
            }

            public List<MIB_UDP6ROW_OWNER_PID> GetAllUDPv6Connections()
            { 
                return GetUDPConnections<MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID>(AF_INET6);
            }

            private static List<IPR> GetTCPConnections<IPR, IPT>(int ipVersion)
            {
                //IPR = Row Type, IPT = Table Type
                IPR[] tableRows;
                int buffSize = 0;
                FieldInfo dwNumEntriesField = typeof(IPT).GetField("dwNumEntries");

                // how much memory do we need?
                _pGetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
                IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);

                try 
                { 
                    uint ret = _pGetExtendedTcpTable(tcpTablePtr, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL); 
                    if (ret != 0) 
                        return new List<IPR>();

                    // get the number of entries in the table
                    IPT table = (IPT)Marshal.PtrToStructure(tcpTablePtr, typeof(IPT));
                    int rowStructSize = Marshal.SizeOf(typeof(IPR));
                    uint numEntries = (uint)dwNumEntriesField.GetValue(table);

                    // buffer we will be returning
                    tableRows = new IPR[numEntries];

                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                    for (int i = 0; i < numEntries; i++) {
                        IPR tcpRow = (IPR)Marshal.PtrToStructure(rowPtr, typeof(IPR));
                        tableRows[i] = tcpRow;
                        rowPtr = (IntPtr)((long)rowPtr + rowStructSize);   // next entry
                    }
                }
                finally 
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
                
                return tableRows != null ? tableRows.ToList() : new List<IPR>();
                
            }
            
            private static List<IPR> GetUDPConnections<IPR, IPT>(int ipVersion)//IPR = Row Type, IPT = Table Type
            {
                IPR[] tableRows;
                int buffSize = 0;

                FieldInfo dwNumEntriesField = typeof(IPT).GetField("dwNumEntries");

                // how much memory do we need?
                _pGetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, ipVersion, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);

                try
                {
                    uint ret = _pGetExtendedUdpTable(tcpTablePtr, ref buffSize, true, ipVersion, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID);
                    if (ret != 0)
                        return new List<IPR>();

                    // get the number of entries in the table
                    IPT table = (IPT)Marshal.PtrToStructure(tcpTablePtr, typeof(IPT));
                    int rowStructSize = Marshal.SizeOf(typeof(IPR));
                    uint numEntries = (uint)dwNumEntriesField.GetValue(table);

                    // buffer we will be returning
                    tableRows = new IPR[numEntries];

                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                    for (int i = 0; i < numEntries; i++)
                    {
                        IPR tcpRow = (IPR)Marshal.PtrToStructure(rowPtr, typeof(IPR));
                        tableRows[i] = tcpRow;
                        rowPtr = (IntPtr)((long)rowPtr + rowStructSize);   // next entry
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
                return tableRows != null ? tableRows.ToList() : new List<IPR>();
            }

            // Occurs on destruction of the Wrapper
            ~IConnectionWrapper() { Dispose(); }
        }
                
        public override void Start()
        { 
            IConnectionWrapper connectionWrapper = new IConnectionWrapper(); 
            List<NetstatEntry> netstat = new List<NetstatEntry>();
            NetstatParameters parameters = _jsonSerializer.Deserialize<NetstatParameters>(_data.Parameters);

            if (!parameters.Udp) 
            {
                foreach (MIB_TCPROW_OWNER_PID tcpEntry in connectionWrapper.GetAllTCPv4Connections()) {
                    if (parameters.Established) 
                    {
                        if (tcpEntry.State != TcpState.Established)
                            continue;
                    }
                 
                    if (parameters.Listen)
                    {
                        if (tcpEntry.State != TcpState.Listen)
                            continue;
                    }
                 
                    netstat.Add(new NetstatEntry {
                        LocalAddress = tcpEntry.LocalAddress.ToString(),
                        RemoteAddress = tcpEntry.RemoteAddress.ToString(),
                        LocalPort = tcpEntry.LocalPort,
                        RemotePort = tcpEntry.RemotePort,
                        Pid = tcpEntry.ProcessId,
                        State = tcpEntry.State.ToString() ,
                        Protocol = "TCP",
                        IpVersion = 4
                    });
                }
            
                foreach (MIB_TCP6ROW_OWNER_PID tcp6Entry in connectionWrapper.GetAllTCPv6Connections()) 
                {
                    if (parameters.Established) 
                    {
                        if (tcp6Entry.State != TcpState.Established)
                            continue;
                    }
                 
                    if (parameters.Listen)
                    {
                        if (tcp6Entry.State != TcpState.Listen)
                            continue;
                    }
                    
                    netstat.Add(new NetstatEntry {
                        LocalAddress = "[" + tcp6Entry.LocalAddress.ToString() + "]",
                        RemoteAddress = "[" + tcp6Entry.RemoteAddress.ToString() + "]",
                        LocalPort = tcp6Entry.LocalPort,
                        RemotePort = tcp6Entry.RemotePort,
                        Pid = tcp6Entry.ProcessId,
                        State = tcp6Entry.State.ToString(),
                        Protocol = "TCP",
                        IpVersion = 6
                    });
                }
            }

            if (!parameters.Tcp && !parameters.Established && !parameters.Listen) 
            {
                foreach (MIB_UDPROW_OWNER_PID udpEntry in connectionWrapper.GetAllUDPv4Connections()) 
                {
                    netstat.Add(new NetstatEntry {
                        LocalAddress = udpEntry.LocalAddress.ToString(),
                        RemoteAddress = "0.0.0.0",
                        LocalPort = udpEntry.LocalPort,
                        RemotePort = 0,
                        Pid = udpEntry.ProcessId,
                        State = null,
                        Protocol = "UDP",
                        IpVersion = 4
                    });
                }
             
                foreach (MIB_UDP6ROW_OWNER_PID udp6Entry in connectionWrapper.GetAllUDPv6Connections()) 
                {
                    netstat.Add(new NetstatEntry {
                        LocalAddress = "[" + udp6Entry.LocalAddress.ToString() + "]",
                        RemoteAddress = "0.0.0.0",
                        LocalPort = udp6Entry.LocalPort,
                        RemotePort = 0,
                        Pid = udp6Entry.ProcessId,
                        State = null,
                        Protocol = "UDP",
                        IpVersion = 6
                    });
                }
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse(
                    _jsonSerializer.Serialize(netstat.ToArray()),
                    true,
                    ""));
        }
    }
}

#endif