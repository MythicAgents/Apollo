using DnsRip.Models;
using System;

namespace DnsRip.Utilites
{
    public class RecordReader
    {
        public RecordReader(RecordHelper helper)
        {
            Name = helper.ReadDomainName();
            Type = (QueryType)helper.ReadUInt16();
            Class = helper.ReadUInt16();
            Ttl = helper.ReadUInt32();
            Record = helper.ReadRecord(Type, helper.ReadUInt16());
        }

        public string Name;
        public QueryType Type;
        public int Class;
        public Record Record;

        public uint Ttl
        {
            get { return Math.Max(0, _ttl); }
            set { _ttl = value; }
        }

        private uint _ttl;
    }
}