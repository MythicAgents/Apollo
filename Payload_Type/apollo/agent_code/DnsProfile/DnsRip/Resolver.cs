using DnsRip.Extensions;
using DnsRip.Models;
using DnsRip.Utilites;
using System;
using System.Collections.Generic;
using System.Net.Sockets;

namespace DnsRip
{
    public class Resolver
    {
        public Resolver(string server) : this(new[] { server })
        { }

        public Resolver(IEnumerable<string> servers)
        {
            Servers = servers;
            Validator = new Validator();
        }

        public int Retries
        {
            get { return _retries == 0 ? 3 : _retries; }
            set { _retries = value; }
        }

        public TimeSpan Timeout
        {
            get { return _timeout.Ticks == 0 ? TimeSpan.FromSeconds(1) : _timeout; }
            set { _timeout = value; }
        }

        public IEnumerable<string> Servers { get; set; }
        public Validator Validator { get; set; }

        private int _retries;
        private TimeSpan _timeout;

        public IEnumerable<ResolveResponse> Resolve(string query, QueryType type)
        {
            var dnsRequest = GetDnsRequest(query, type);
            var resolved = new List<ResolveResponse>();

            foreach (var server in Servers)
            {
                var attempts = 0;

                while (attempts <= _retries)
                {
                    attempts++;

                    try
                    {
                        using (var socket = new SocketHelper(dnsRequest, server, _timeout))
                        {
                            var data = socket.Send();
                            var dnsResponse = new DnsResponse(data);

                            foreach (var resp in dnsResponse.Answers)
                            {
                                resolved.Add(new ResolveResponse
                                {
                                    Server = server,
                                    Host = resp.Name.FromNameFormat(),
                                    Type = resp.Type,
                                    Record = resp.Record.ToString(),
                                    Ttl = resp.Ttl
                                });
                            }
                        }

                        break;
                    }
                    catch (SocketException)
                    {
                        if (attempts >= 3)
                            throw;
                    }
                }
            }

            return resolved;
        }

        private DnsRequest GetDnsRequest(string query, QueryType type)
        {
            if (type == QueryType.PTR && Validator.IsIp(query))
                query = query.ToArpaRequest();

            var dnsHeader = new DnsHeader();
            var dnsQuestion = new DnsQuestion(query, type);

            return new DnsRequest(dnsHeader, dnsQuestion);
        }
    }
}
