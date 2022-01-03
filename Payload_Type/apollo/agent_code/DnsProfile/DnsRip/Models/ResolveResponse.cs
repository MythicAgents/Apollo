namespace DnsRip.Models
{
    public class ResolveResponse
    {
        public string Server { get; set; }
        public string Host { get; set; }
        public uint Ttl { get; set; }
        public QueryType Type { get; set; }
        public string Record { get; set; }
    }
}