using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsRip.Extensions
{
    internal static class Extensions
    {
        internal static IEnumerable<byte> ToNetByteOrder(this ushort value)
        {
            return BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)value));
        }

        internal static IEnumerable<byte> ToNetByteOrder(this QueryType value)
        {
            return ((ushort)value).ToNetByteOrder();
        }

        internal static IEnumerable<byte> ToNetByteOrder(this int value)
        {
            return ((ushort)value).ToNetByteOrder();
        }

        internal static string ToNameFormat(this string query)
        {
            if (!query.EndsWith("."))
                query += ".";

            return query;
        }

        internal static string FromNameFormat(this string query)
        {
            if (query.EndsWith("."))
                query = query.TrimEnd('.');

            return query;
        }

        internal static string ToArpaRequest(this string query)
        {
            IPAddress ip;

            if (!IPAddress.TryParse(query, out ip))
                return query;

            var result = new StringBuilder();

            switch (ip.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        result.Append("in-addr.arpa.");

                        foreach (var b in ip.GetAddressBytes())
                            result.Insert(0, $"{b}.");

                        return result.ToString();
                    }
                case AddressFamily.InterNetworkV6:
                    {
                        result.Append("ip6.arpa.");

                        foreach (var b in ip.GetAddressBytes())
                        {
                            result.Insert(0, $"{(b >> 4) & 0xf:x}.");
                            result.Insert(0, $"{(b >> 0) & 0xf:x}.");
                        }

                        return result.ToString();
                    }
            }

            return query;
        }
    }
}
