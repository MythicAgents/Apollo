using System;
using System.Runtime.InteropServices;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;

namespace DInvokeResolver
{
    public class DInvokeResolver : IWin32ApiResolver
    {
        public T GetLibraryFunction<T>(Library library, string functionName, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionName, canLoadFromDisk, resolveForwards);
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }

        public T GetLibraryFunction<T>(Library library, short ordinal, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), ordinal, canLoadFromDisk, resolveForwards);
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }

        public T GetLibraryFunction<T>(Library library, string functionHash, long key, bool canLoadFromDisk = true, bool resolveForwards = true) where T : Delegate
        {
            IntPtr fn = DInvoke.DynamicInvoke.Generic.GetLibraryAddress(library.ToString(), functionHash, key, canLoadFromDisk, resolveForwards);
            return (T)Marshal.GetDelegateForFunctionPointer(fn, typeof(T));
        }
    }
}