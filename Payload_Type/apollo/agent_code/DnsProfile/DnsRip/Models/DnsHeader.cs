using DnsRip.Extensions;
using DnsRip.Utilites;
using System;
using System.Collections.Generic;

namespace DnsRip.Models
{
    public class DnsHeader
    {
        public DnsHeader()
        {
            _id = (ushort)new Random().Next();

            OpCode = 0;
            QdCount = 1;
            Recursive = true;
        }

        public DnsHeader(RecordHelper helper)
        {
            _id = helper.ReadUInt16();
            _flags = helper.ReadUInt16();

            QdCount = helper.ReadUInt16();
            AnCount = helper.ReadUInt16();
            NsCount = helper.ReadUInt16();
            ArCount = helper.ReadUInt16();
        }

        public ushort QdCount;
        public ushort AnCount;
        public ushort NsCount;
        public ushort ArCount;

        public int OpCode
        {
            get { return GetBits(_flags, 11, 4); }
            set { _flags = SetBits(_flags, 11, 4, (ushort)value); }
        }

        public bool Recursive
        {
            get { return GetBits(_flags, 8, 1) == 1; }
            set { _flags = SetBits(_flags, 8, 1, value); }
        }

        public byte[] Data
        {
            get
            {
                var data = new List<byte>();

                data.AddRange(_id.ToNetByteOrder());
                data.AddRange(_flags.ToNetByteOrder());
                data.AddRange(QdCount.ToNetByteOrder());
                data.AddRange(AnCount.ToNetByteOrder());
                data.AddRange(NsCount.ToNetByteOrder());
                data.AddRange(ArCount.ToNetByteOrder());

                return data.ToArray();
            }
        }

        private readonly ushort _id;
        private ushort _flags;

        private static ushort GetBits(ushort oldValue, int position, int length)
        {
            if (length <= 0 || position >= 16)
                return 0;

            var mask = (2 << (length - 1)) - 1;

            return (ushort)((oldValue >> position) & mask);
        }

        private static ushort SetBits(ushort oldValue, int position, int length, ushort newValue)
        {
            if (length <= 0 || position >= 16)
                return oldValue;

            var mask = (2 << (length - 1)) - 1;

            oldValue &= (ushort)~(mask << position);
            oldValue |= (ushort)((newValue & mask) << position);

            return oldValue;
        }

        private static ushort SetBits(ushort oldValue, int position, int length, bool blnValue)
        {
            return SetBits(oldValue, position, length, blnValue ? (ushort)1 : (ushort)0);
        }
    }
}