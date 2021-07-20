using DnsRip.Utilites;

namespace DnsRip.Models
{
    public class RecordNs : Record
    {
        public RecordNs(RecordHelper helper)
        {
            _value = helper.ReadDomainName();
        }

        private readonly string _value;

        public override string ToString()
        {
            return _value;
        }
    }
}