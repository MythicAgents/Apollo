using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Management;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace Apollo.Utils
{

    /// <summary>
    /// Shamelessly lifted from SharpWMI
    /// </summary>
    public static class WMIUtils
    {
        // helper used to wrap long output
        public static System.Collections.Generic.IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        public static bool LocalWMIQuery(string wmiQuery, out string[] results, string wmiNameSpace = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            ManagementObjectSearcher wmiData = null;

            try
            {
                if (String.IsNullOrEmpty(wmiNameSpace))
                {
                    wmiData = new ManagementObjectSearcher(wmiQuery);
                }
                else
                {
                    wmiData = new ManagementObjectSearcher(wmiNameSpace, wmiQuery);
                }

                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        string propValue = String.Format("{0}", prop.Value);

                        // wrap long output to 80 lines
                        if (!String.IsNullOrEmpty(propValue) && (propValue.Length > 90))
                        {
                            bool header = false;
                            foreach (string line in Split(propValue, 80))
                            {
                                if (!header)
                                {
                                    output.Add(String.Format("{0,30} : {1}", prop.Name, line));
                                }
                                else
                                {
                                    output.Add(String.Format("{0,30}   {1}", "", line));
                                }
                                header = true;
                            }
                        }
                        else
                        {
                            output.Add(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                        }
                    }
                }
                bRet = true;
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

        public static bool RemoteWMIQuery(string host, string wmiQuery, out string[] results, string wmiNameSpace = "", string username = "", string password = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            if (string.IsNullOrEmpty(wmiNameSpace))
            {
                wmiNameSpace = "root\\cimv2";
            }

            ConnectionOptions options = new ConnectionOptions();

            output.Add(string.Format("Scope: \\\\{0}\\{1}", host, wmiNameSpace));

            if (!String.IsNullOrEmpty(username))
            {
                output.Add(string.Format("User credentials: {0}", username));
                options.Username = username;
                options.Password = password;
            }
            output.Add("");

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                output.Add("");

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        output.Add(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                    }
                    output.Add("");
                }
                bRet = true;
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

        public static bool RemoteWMIExecute(string host, string command, out string[] results, string username = "", string password = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            string wmiNameSpace = "root\\cimv2";

            ConnectionOptions options = new ConnectionOptions();

            output.Add(string.Format("Host                           : {0}", host));
            output.Add(string.Format("Command                        : {0}", command));

            if (!String.IsNullOrEmpty(username))
            {
                output.Add(string.Format("User credentials               : {0}", username));
                options.Username = username;
                options.Password = password;
            } else
            {
                options.Authority = "kerberos:LAB";
            }
            output.Add("");

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
                System.Management.PropertyDataCollection properties = inParams.Properties;

                inParams["CommandLine"] = command;

                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                output.Add(string.Format("Creation of process returned   : {0}", outParams["returnValue"]));
                output.Add(string.Format("Process ID                     : {0}", outParams["processId"]));
                bRet = true;
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

        public static bool RemoteWMIProcessKill(string host, string processNameOrPid, out string[] results, string username = "", string password = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            int pid = 0;
            bool parseResult = int.TryParse(processNameOrPid, out pid);

            string wmiNameSpace = "root\\cimv2";

            ConnectionOptions options = new ConnectionOptions();

            output.Add(String.Format("\r\n  Scope: \\\\{0}\\{1}", host, wmiNameSpace));

            if (!String.IsNullOrEmpty(username))
            {
                output.Add(string.Format("User credentials: {0}", username));
                options.Username = username;
                options.Password = password;
            }
            output.Add("");

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                string queryStr = "";
                if (pid == 0)
                {
                    queryStr = $"Select * from Win32_Process where Name='{processNameOrPid}'";
                }
                else
                {
                    queryStr = $"Select * from Win32_Process where ProcessId='{pid}'";
                }
                ObjectQuery query = new ObjectQuery(queryStr);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                output.Add("");

                if (data.Count == 0)
                {
                    output.Add($"[X] No process found with the name/PID '{processNameOrPid}'");
                }
                else
                {
                    foreach (ManagementObject result in data)
                    {
                        System.Management.PropertyDataCollection props = result.Properties;

                        output.Add($"[+] Terminating {props["name"].Value} (PID {props["ProcessId"].Value})");
                        result.InvokeMethod("Terminate", new object[] { });
                    }
                    bRet = true;
                }
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

        public static bool RemoteWMIFirewall(string host, out string[] results, string username = "", string password = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            string wmiNameSpace = "ROOT\\StandardCIMV2";

            ConnectionOptions options = new ConnectionOptions();

            output.Add(string.Format("Scope: \\\\{0}\\{1}", host, wmiNameSpace));

            if (!String.IsNullOrEmpty(username))
            {
                output.Add(string.Format("User credentials: {0}", username));
                options.Username = username;
                options.Password = password;
            }
            output.Add("");

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            Dictionary<string, ArrayList> firewallRules = new Dictionary<string, ArrayList>();

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery("SELECT Enabled,DisplayName,Action,Direction,InstanceID from MSFT_NetFirewallRule WHERE Enabled=1");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;

                    string instanceID = props["InstanceID"].Value.ToString();

                    ArrayList ruleData = new ArrayList();
                    ruleData.Add(props["DisplayName"].Value.ToString());
                    ruleData.Add(props["Action"].Value.ToString());
                    ruleData.Add(props["Direction"].Value.ToString());

                    firewallRules[instanceID] = ruleData;
                }

                ObjectQuery query2 = new ObjectQuery("SELECT InstanceID,LocalPort from MSFT_NetProtocolPortFilter WHERE Protocol='TCP'");
                ManagementObjectSearcher searcher2 = new ManagementObjectSearcher(scope, query2);
                ManagementObjectCollection data2 = searcher2.Get();
                foreach (ManagementObject result in data2)
                {
                    System.Management.PropertyDataCollection props = result.Properties;

                    if ((props["LocalPort"].Value != null))
                    {
                        string instanceID = props["InstanceID"].Value.ToString();
                        if (firewallRules.ContainsKey(instanceID))
                        {
                            string[] localPorts = (string[])props["LocalPort"].Value;

                            output.Add(string.Format("Rulename   : {0}", firewallRules[instanceID][0]));
                            if (firewallRules[instanceID][1].ToString() == "2")
                            {
                                output.Add(string.Format("Action     : {0} (Allow)", firewallRules[instanceID][1]));
                            }
                            else if (firewallRules[instanceID][1].ToString() == "3")
                            {
                                output.Add(string.Format("Action     : {0} (AllowBypass)", firewallRules[instanceID][1]));
                            }
                            else if (firewallRules[instanceID][1].ToString() == "4")
                            {
                                output.Add(string.Format("Action     : {0} (Block)", firewallRules[instanceID][1]));
                            }
                            else
                            {
                                output.Add(string.Format("Action     : {0} (Unknown)", firewallRules[instanceID][1]));
                            }

                            if (firewallRules[instanceID][2].ToString() == "1")
                            {
                                output.Add(string.Format("Direction  : {0} (Inbound)", firewallRules[instanceID][2]));
                            }
                            else if (firewallRules[instanceID][2].ToString() == "2")
                            {
                                output.Add(string.Format("Direction  : {0} (Outbound)", firewallRules[instanceID][2]));
                            }
                            else
                            {
                                output.Add(string.Format("Direction  : {0} (Unknown)", firewallRules[instanceID][2]));
                            }

                            output.Add(string.Format("LocalPorts : {0}\n", localPorts));
                        }
                    }
                }
                bRet = true;
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

        public static bool RemoteWMIExecuteVBS(string host, string eventName, string vbsPayload, out string[] results, string username = "", string password = "")
        {
            bool bRet = false;
            List<string> output = new List<string>();
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (!String.IsNullOrEmpty(username))
                {
                    output.Add(string.Format("[*] User credentials: {0}", username));
                    options.Username = username;
                    options.Password = password;
                }

                // first create a 30 second timer on the remote host
                ManagementScope timerScope = new ManagementScope(string.Format(@"\\{0}\root\cimv2", host), options);
                ManagementClass timerClass = new ManagementClass(timerScope, new ManagementPath("__IntervalTimerInstruction"), null);
                ManagementObject myTimer = timerClass.CreateInstance();
                myTimer["IntervalBetweenEvents"] = (UInt32)30000;
                myTimer["SkipIfPassed"] = false;
                myTimer["TimerId"] = "Timer";
                try
                {
                    output.Add(string.Format("[*] Creating 'Timer' object on {0}", host));
                    myTimer.Put();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in creating timer object: {0}", ex.Message));
                    results = output.ToArray();
                    return bRet;
                }

                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\root\subscription", host), options);

                // then install the __EventFilter for the timer object
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(@"SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'");
                ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = eventName;
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                try
                {
                    output.Add(string.Format("[*] Setting '{0}' event filter on {1}", eventName, host));
                    myEventFilter.Put();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in setting event filter: {0}", ex.Message));
                }


                // now create the ActiveScriptEventConsumer payload (VBS)
                ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();

                myEventConsumer["Name"] = eventName;
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = vbsPayload;
                myEventConsumer["KillTimeout"] = (UInt32)45;

                try
                {
                    output.Add(string.Format("[*] Setting '{0}' event consumer on {1}", eventName, host));
                    myEventConsumer.Put();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in setting event consumer: {0}", ex.Message));
                }


                // finally bind them together with a __FilterToConsumerBinding
                ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;

                try
                {
                    output.Add(string.Format("[*] Binding '{0}' event filter and consumer on {1}", eventName, host));
                    myBinder.Put();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in setting FilterToConsumerBinding: {0}", ex.Message));
                }


                // wait for everything to trigger
                output.Add(string.Format("\r\n[*] Waiting 45 seconds for event to trigger on {0} ...\r\n", host));
                System.Threading.Thread.Sleep(45 * 1000);


                // finally, cleanup
                try
                {
                    output.Add(string.Format("[*] Removing 'Timer' internal timer from {0}", host));
                    myTimer.Delete();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in removing 'Timer' interval timer: {0}", ex.Message));
                }

                try
                {
                    output.Add(string.Format("[*] Removing FilterToConsumerBinding from {0}", host));
                    myBinder.Delete();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in removing FilterToConsumerBinding: {0}", ex.Message));
                }

                try
                {
                    output.Add(string.Format("[*] Removing '{0}' event filter from {1}", eventName, host));
                    myEventFilter.Delete();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in removing event filter: {0}", ex.Message));
                }

                try
                {
                    output.Add(string.Format("[*] Removing '{0}' event consumer from {0}\r\n", eventName, host));
                    myEventConsumer.Delete();
                }
                catch (Exception ex)
                {
                    output.Add(string.Format("[X] Exception in removing event consumer: {0}", ex.Message));
                }
                bRet = true;
            }
            catch (Exception ex)
            {
                output.Add(String.Format("Exception : {0}", ex.Message));
            }
            results = output.ToArray();
            return bRet;
        }

    }
}
