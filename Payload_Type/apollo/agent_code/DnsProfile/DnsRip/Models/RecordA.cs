using DnsRip.Utilites;
using System.Net;

namespace DnsRip.Models
{
    public class RecordA : Record
    {
        public RecordA(RecordHelper helper)
        {
            _value = new IPAddress(helper.ReadBytes(4));
        }

        private readonly IPAddress _value;

        public override string ToString()
        {
            return _value.ToString();
        }
    }
}