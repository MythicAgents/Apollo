using DnsRip.Models;
using System.Text.RegularExpressions;

namespace DnsRip
{
    public class Parser
    {
        public ParseResult Parse(string input)
        {
            var result = new ParseResult
            {
                Input = input,
                Evaluated = input.Trim().ToLower()
            };

            var match = Regex.Match(result.Evaluated, @"((?:[0-9]{1,3}\.){3}[0-9]{1,3}|([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4})");

            if (match.Success)
            {
                result.Type = InputType.Ip;
                result.Parsed = match.Value;
                return result;
            }

            match = Regex.Match(result.Evaluated, @"((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))($|\.|/|:)");

            if (match.Success)
            {
                result.Type = InputType.Hostname;
                result.Parsed = match.Groups[1].Value;
                return result;
            }

            result.Type = InputType.Invalid;
            return result;
        }
    }
}
