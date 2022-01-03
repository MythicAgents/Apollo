using DnsRip.Utilites;
using System.Collections.Generic;
using System.Text;

namespace DnsRip.Models
{
    public class RecordTxt : Record
    {
        public RecordTxt(RecordHelper helper, int length)
        {
            var pos = helper.Position;

            _value = new List<string>();

            while (helper.Position - pos < length)
                _value.Add(helper.ReadString());
        }

        private readonly List<string> _value;

        public override string ToString()
        {
            var sb = new StringBuilder();

            foreach (var txt in _value)
                sb.AppendFormat("\"{0}\" ", txt);

            return sb.ToString().TrimEnd();
        }
    }
}