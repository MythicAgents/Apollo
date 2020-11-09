using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceProcess;
using Native;
using Utils;
using static Utils.DebugUtils;
using System.Diagnostics;

namespace Apollo.Utils
{
    internal static class ServiceUtils
    {
        internal static bool GetService(string computerName, string serviceName, out ServiceController service)
        {
            bool bRet = false;
            service = null;
            string lServiceName = serviceName.ToLower();
            ServiceController[] services = ServiceController.GetServices(computerName);
            foreach(var s in services)
            {
                if (s.ServiceName.ToLower() == lServiceName)
                {
                    bRet = true;
                    service = s;
                    break;
                }
            }
            return bRet;
        }

        public static bool StopService(string computerName, string serviceName)
        {
            bool bRet = false;
            var serviceInstance = new ServiceController(serviceName, computerName);
            if (serviceInstance.Status == ServiceControllerStatus.Stopped || serviceInstance.Status == ServiceControllerStatus.StopPending)
            {
                DebugWriteLine("[-] {0} on {1} is already stopped. Current status: {2}", serviceInstance.ServiceName, computerName, serviceInstance.Status.ToString());
                Environment.Exit(0);
            }
            DebugWriteLine("[*] Attempting to stop service {0} on {1}...", serviceInstance.ServiceName, computerName);
            serviceInstance.Stop();
            serviceInstance.WaitForStatus(ServiceControllerStatus.Stopped);
            bRet = true;
            //Console.WriteLine("[+] Successfully stopped {0} on {1}!", serviceInstance.ServiceName, computerName);
            //Console.WriteLine();
            //Console.WriteLine("\tDisplayName: {0}", serviceInstance.DisplayName);
            //Console.WriteLine("\tServiceName: {0}", serviceInstance.ServiceName);
            //Console.WriteLine("\tStatus     : {0}", serviceInstance.Status);
            //Console.WriteLine("\tCanStop    : {0}", serviceInstance.CanStop);
            return bRet;
        }

        public static bool StartService(string computerName, string serviceName)
        {
            bool bRet = false;
            var serviceInstance = new ServiceController(serviceName, computerName);
            if (serviceInstance.Status == ServiceControllerStatus.Running || serviceInstance.Status == ServiceControllerStatus.StartPending)
            {
                DebugWriteLine($"[-] Service {serviceInstance.ServiceName} on {computerName} is already running. Current status: {serviceInstance.Status.ToString()}");
                return bRet;
            }
            DebugWriteLine($"[*] Attempting to start service {serviceInstance.ServiceName} on {computerName}...");
            serviceInstance.Start();
            bRet = true;
            return bRet;
        }

        public static bool StartService(string computerName, string serviceName, ServiceControllerStatus status)
        {
            bool bRet = false;
            var serviceInstance = new ServiceController(serviceName, computerName);
            if (serviceInstance.Status == ServiceControllerStatus.Running || serviceInstance.Status == ServiceControllerStatus.StartPending)
            {
                DebugWriteLine($"[-] Service {serviceInstance.ServiceName} on {computerName} is already running. Current status: {serviceInstance.Status.ToString()}");
                return bRet;
            }
            DebugWriteLine($"[*] Attempting to start service {serviceInstance.ServiceName} on {computerName}...");
            serviceInstance.Start();
            serviceInstance.WaitForStatus(status, TimeSpan.FromSeconds(30));
            bRet = true;
            return bRet;
        }

        public static bool InstallService(string hostname, string serviceName, string serviceDisplayName, string serviceExe)
        {
            bool bRet = false;
            try
            {
                UninstallService(hostname, serviceName);
            }
            catch (Exception ex) { }
            DebugWriteLine($"[*] Attempting to create service {serviceName} on {hostname}...");
            using (var scmHandle = Methods.OpenSCManager(hostname, null, Enums.SCM_ACCESS.SC_MANAGER_CREATE_SERVICE))
            {
                if (scmHandle.IsInvalid)
                {
                    DebugWriteLine("[-] Error retrieving a handle to the ServiceControlManager. Reason: Invalid Handle.");
                    return bRet;
                }

                using (
                    var serviceHandle = Methods.CreateService(
                        scmHandle,
                        serviceName,
                        serviceDisplayName,
                        Enums.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                        Enums.SERVICE_TYPES.SERVICE_WIN32_OWN_PROCESS,
                        Enums.SERVICE_START_TYPES.SERVICE_AUTO_START,
                        Enums.SERVICE_ERROR_CONTROL.SERVICE_ERROR_NORMAL,
                        serviceExe,
                        null,
                        IntPtr.Zero,
                        null,
                        null,
                        null))
                {
                    if (serviceHandle.IsInvalid)
                    {
                        DebugWriteLine("[-] Error creating service: received an invalid handle.");
                        return bRet;
                    }

                    DebugWriteLine($"[*] Created {serviceName} Service on {hostname}");
                    bRet = true;
                }
            }
            return bRet;
        }

        public static bool UninstallService(string hostname, string ServiceName)
        {
            bool bRet = false;
            using (var scmHandle = Methods.OpenSCManager(hostname, null, Enums.SCM_ACCESS.SC_MANAGER_CREATE_SERVICE))
            {
                if (scmHandle.IsInvalid)
                {
                    DebugWriteLine($"[-] Error uninstalling {ServiceName} on {hostname}. Reason: Invalid Handle.");
                    return bRet;
                }
                using (var serviceHandle = Methods.OpenService(scmHandle, ServiceName, Enums.SERVICE_ACCESS.SERVICE_ALL_ACCESS))
                {
                    if (serviceHandle.IsInvalid)
                    {
                        DebugWriteLine($"[-] Error uninstalling {ServiceName} on {hostname}. Reason: ServiceHandle is invalid.");
                        return bRet;
                    }
                    DebugWriteLine($"[*] Attempting to delete {ServiceName} on {hostname}...");
                    Methods.DeleteService(serviceHandle);
                    DebugWriteLine($"[*] Deleted {ServiceName} on {hostname}.");
                    bRet = true;
                }
            }
            return bRet;
        }


    }
}
