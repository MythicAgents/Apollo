using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Runtime.InteropServices;
#if NET_v4
using System.Runtime.ExceptionServices;
#endif
using System.Runtime.CompilerServices;


[assembly:RuntimeCompatibility(WrapNonExceptionThrows = true)]
namespace DemoAssembly
{
    
    public class Demo
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void Fptr([MarshalAs(UnmanagedType.LPWStr)]string val);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int ClsPtr(IntPtr tptr);

        [UnmanagedFunctionPointer(CallingConvention.ThisCall)]
        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int ClsPtr2(IntPtr tptr, [MarshalAs(UnmanagedType.LPWStr)]string val);

        private IntPtr is_this_;

        public Demo()
        {
        }

        public static void Popup(string msg)
        {
            MessageBox.Show(msg);
        }

        public void Callback(Int64 ptr)
        {
            IntPtr p = (IntPtr)ptr;
            Fptr cb = (Fptr)Marshal.GetDelegateForFunctionPointer(p, typeof(Fptr));

            cb("Made it here!");
            
        }

        public string GetString()
        {
            return "This is what we return.";
        }


#if NET_v4
        [HandleProcessCorruptedStateExceptions]
#endif
        public void ExceptionCallback(Int64 ptr)
        {
            IntPtr p = (IntPtr)ptr;
            Fptr ecb = (Fptr)Marshal.GetDelegateForFunctionPointer(p, typeof(Fptr));
            try
            {
                ecb("This will segfault!");
            }
            catch(Exception e)
            {
                MessageBox.Show("Handled!" + e);
            }
        }


        public bool AddClass(Int64 tptr)
        {
            is_this_ = (IntPtr)tptr;
            return true;
        }

        public void InvokeMethod(Int64 fptr)
        {
            ClsPtr p = (ClsPtr)Marshal.GetDelegateForFunctionPointer((IntPtr)fptr, typeof(ClsPtr));
            int res = p(is_this_);

            MessageBox.Show("Value: " + res);
        }

        public void InvokeExcepted(Int64 fptr)
        {
            ClsPtr2 p = (ClsPtr2)Marshal.GetDelegateForFunctionPointer((IntPtr)fptr, typeof(ClsPtr2));
            try
            {
                int res = p(is_this_, "Here we go...");
            }
            catch(Exception e)
            {
                MessageBox.Show("Handled CPP exception!");
            }
        }
    }

}
