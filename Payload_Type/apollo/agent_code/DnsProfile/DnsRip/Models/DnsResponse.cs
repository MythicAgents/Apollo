using DnsRip.Utilites;
using System.Collections.Generic;

namespace DnsRip.Models
{
    public class DnsResponse
    {
        public DnsResponse(byte[] data)
        {
            var record = new RecordHelper(data);
            var header = new DnsHeader(record);

            Questions = new List<DnsQuestion>();
            Answers = new List<AnswerReader>();
            Authorities = new List<AuthorityReader>();
            Additionals = new List<AdditionalReader>();

            for (var intI = 0; intI < header.QdCount; intI++)
            {
                Questions.Add(new DnsQuestion(record));
            }

            for (var intI = 0; intI < header.AnCount; intI++)
            {
                Answers.Add(new AnswerReader(record));
            }

            for (var intI = 0; intI < header.NsCount; intI++)
            {
                Authorities.Add(new AuthorityReader(record));
            }

            for (var intI = 0; intI < header.ArCount; intI++)
            {
                Additionals.Add(new AdditionalReader(record));
            }
        }

        public List<DnsQuestion> Questions;
        public List<AnswerReader> Answers;
        public List<AuthorityReader> Authorities;
        public List<AdditionalReader> Additionals;
    }
}