using DnsRip.Utilites;

namespace DnsRip.Models
{
    public class RecordSoa : Record
    {
        public RecordSoa(RecordHelper helper)
        {
            _mName = helper.ReadDomainName();
            _rName = helper.ReadDomainName();
            _serial = helper.ReadUInt32();
            _refresh = helper.ReadUInt32();
            _retry = helper.ReadUInt32();
            _expire = helper.ReadUInt32();
            _minimum = helper.ReadUInt32();
        }

        private readonly string _mName;
        private readonly string _rName;
        private readonly uint _serial;
        private readonly uint _refresh;
        private readonly uint _retry;
        private readonly uint _expire;
        private readonly uint _minimum;

        public override string ToString()
        {
            return $"{_mName} {_rName} {_serial} {_refresh} {_retry} {_expire} {_minimum}";
        }
    }
}