using DnsRip.Extensions;
using DnsRip.Utilites;
using System.Collections.Generic;
using System.Text;

namespace DnsRip.Models
{
    public class DnsQuestion
    {
        public DnsQuestion(string query, QueryType type)
        {
            Query = query;

            _type = type;
            _class = 1;
        }

        public DnsQuestion(RecordHelper helper)
        {
            Query = helper.ReadDomainName();

            _type = (QueryType)helper.ReadUInt16();
            _class = helper.ReadUInt16();
        }

        public byte[] Data
        {
            get
            {
                var data = new List<byte>();

                data.AddRange(QueryToBytes());
                data.AddRange(_type.ToNetByteOrder());
                data.AddRange(_class.ToNetByteOrder());

                return data.ToArray();
            }
        }

        private string Query
        {
            get { return _query; }
            set { _query = value.ToNameFormat(); }
        }

        private string _query;
        private readonly QueryType _type;
        private readonly int _class;

        private IEnumerable<byte> QueryToBytes()
        {
            var query = Query.ToNameFormat();

            if (query == ".")
                return new byte[1];

            var sb = new StringBuilder();
            int i, j, len = query.Length;

            sb.Append('\0');

            for (i = 0, j = 0; i < len; i++, j++)
            {
                sb.Append(query[i]);

                if (query[i] != '.')
                    continue;

                sb[i - j] = (char)(j & 0xff);
                j = -1;
            }

            sb[sb.Length - 1] = '\0';

            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        public override string ToString()
        {
            return $"{Query,-32}\t{_class}\t{_type}";
        }
    }
}