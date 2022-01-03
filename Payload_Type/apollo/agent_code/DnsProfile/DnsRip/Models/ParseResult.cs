namespace DnsRip.Models
{
    public class ParseResult
    {
        public string Input { get; set; }
        public string Evaluated { get; set; }
        public string Parsed { get; set; }
        public InputType Type { get; set; }
    }
}