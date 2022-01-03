using System;

namespace DnsRip.Utilites
{
    public class Validator
    {
        public bool IsInteger(object query)
        {
            int integer;
            return int.TryParse(query.ToString(), out integer);
        }

        public bool IsIp4(string query)
        {
            return Uri.CheckHostName(query) == UriHostNameType.IPv4;
        }

        public bool IsIp6(string query)
        {
            return Uri.CheckHostName(query) == UriHostNameType.IPv6;
        }

        public bool IsIp(string query)
        {
            return Uri.CheckHostName(query) == UriHostNameType.IPv4 ||
                Uri.CheckHostName(query) == UriHostNameType.IPv6;
        }

        public bool IsDomain(string query)
        {
            return Uri.CheckHostName(query) == UriHostNameType.Dns;
        }

        public bool IsMx(string query)
        {
            if (!query.Contains(" "))
                return false;

            var pref = query.Split(' ')[0];
            var ex = query.Split(' ')[1];

            return IsInteger(pref) && IsDomain(ex);
        }

        public bool IsSoa(string query)
        {
            if (!query.Contains(" "))
                return false;

            var values = query.Split(' ');
            var index = 0;

            foreach (var value in values)
            {
                index++;

                if (index <= 2 && !IsDomain(value))
                    return false;

                if (index > 2 && !IsInteger(value))
                    return false;
            }

            return true;
        }
    }
}
