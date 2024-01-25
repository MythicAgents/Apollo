using System.Runtime.Serialization;

namespace WebsocketTransport.Models
{
    [DataContract]
    public class WebSocketMessage
    {
        [DataMember]
        public bool client { get; set; }

        [DataMember]
        public string data { get; set; }

        [DataMember]
        public string tag { get; set; }
    }

    public partial class WebsocketJsonContext
    {
    }
}