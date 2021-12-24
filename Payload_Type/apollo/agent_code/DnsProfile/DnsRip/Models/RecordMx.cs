using DnsRip.Utilites;

namespace DnsRip.Models
{
    public class RecordMx : Record
    {
        public RecordMx(RecordHelper helper)
        {
            _preference = helper.ReadUInt16();
            _exchange = helper.ReadDomainName();
        }

        private readonly ushort _preference;
        private readonly string _exchange;

        public override string ToString()
        {
            return $"{_preference} {_exchange}";
        }
    }
}