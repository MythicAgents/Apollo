using DnsRip.Models;
using System;
using System.Net;
using System.Net.Sockets;

namespace DnsRip.Utilites
{
    public class SocketHelper : IDisposable
    {
        public SocketHelper(DnsRequest request, string server, TimeSpan timeout)
        {
            _request = request;
            _server = new IPEndPoint(IPAddress.Parse(server), 53);
            _timeout = timeout;
        }

        private Socket _socket;
        private readonly IPEndPoint _server;
        private readonly DnsRequest _request;
        private readonly TimeSpan _timeout;

        public byte[] Send()
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
            _socket.SendTo(_request.Data, _server);

            var buffer = new byte[512];
            var received = _socket.Receive(buffer);
            var data = new byte[received];

            Array.Copy(buffer, data, received);

            return data;
        }

        public void Dispose()
        {
            _socket.Dispose();
        }
    }
}
