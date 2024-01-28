using Newtonsoft.Json;

namespace WebsocketTransport.Models
{
    public class WebSocketMessage
    {
        public bool client { get; set; }
        public string data { get; set; }
        public string tag { get; set; }
    }

    public class WebsocketJsonContext
    {
        public static string Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj);
        }

        public static T Deserialize<T>(string json)
        {
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
