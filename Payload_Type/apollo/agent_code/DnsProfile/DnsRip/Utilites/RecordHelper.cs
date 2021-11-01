using DnsRip.Models;
using System.Text;

namespace DnsRip.Utilites
{
    public class RecordHelper
    {
        public RecordHelper(byte[] data)
        {
            _data = data;
            Position = 0;
        }

        public RecordHelper(byte[] data, int position)
        {
            _data = data;
            Position = position;
        }

        public int Position { get; set; }

        private readonly byte[] _data;

        public string ReadDomainName()
        {
            var sb = new StringBuilder();
            int length;

            while ((length = ReadByte()) != 0)
            {
                if ((length & 0xc0) == 0xc0)
                {
                    var helper = new RecordHelper(_data, (length & 0x3f) << 8 | ReadByte());

                    sb.Append(helper.ReadDomainName());

                    return sb.ToString();
                }

                while (length > 0)
                {
                    sb.Append(ReadChar());
                    length--;
                }

                sb.Append('.');
            }

            return sb.Length == 0 ? "." : sb.ToString();
        }

        public string ReadString()
        {
            var length = ReadByte();
            var sb = new StringBuilder();

            for (var intI = 0; intI < length; intI++)
                sb.Append(ReadChar());

            return sb.ToString();
        }

        public byte ReadByte()
        {
            return Position >= _data.Length ? (byte)0 : _data[Position++];
        }

        public byte[] ReadBytes(int intLength)
        {
            var list = new byte[intLength];

            for (var intI = 0; intI < intLength; intI++)
                list[intI] = ReadByte();

            return list;
        }

        public char ReadChar()
        {
            return (char)ReadByte();
        }

        public ushort ReadUInt16()
        {
            return (ushort)(ReadByte() << 8 | ReadByte());
        }

        public ushort ReadUInt16(int offset)
        {
            Position += offset;

            return ReadUInt16();
        }

        public uint ReadUInt32()
        {
            return (uint)(ReadUInt16() << 16 | ReadUInt16());
        }

        public Record ReadRecord(QueryType type, int length)
        {
            switch (type)
            {
                case QueryType.A:
                    return new RecordA(this);

                case QueryType.CNAME:
                    return new RecordCName(this);

                case QueryType.AAAA:
                    return new RecordAaaa(this);

                case QueryType.NS:
                    return new RecordNs(this);

                case QueryType.MX:
                    return new RecordMx(this);

                case QueryType.SOA:
                    return new RecordSoa(this);

                case QueryType.TXT:
                    return new RecordTxt(this, length);

                case QueryType.PTR:
                    return new RecordPtr(this);

                default:
                    return new RecordUnknown();
            }
        }
    }
}