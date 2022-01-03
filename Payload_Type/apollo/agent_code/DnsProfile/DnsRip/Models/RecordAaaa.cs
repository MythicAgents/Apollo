using DnsRip.Utilites;
using System.Net;

namespace DnsRip.Models
{
    public class RecordAaaa : Record
    {
        public RecordAaaa(RecordHelper helper)
        {
            IPAddress.TryParse(
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}:" +
                $"{helper.ReadUInt16():x}",
                out _value);
        }

        private readonly IPAddress _value;

        public override string ToString()
        {
            return _value.ToString();
        }
    }
}