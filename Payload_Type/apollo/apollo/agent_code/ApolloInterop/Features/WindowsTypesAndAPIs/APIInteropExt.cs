using System;

namespace ApolloInterop.Features.WindowsTypesAndAPIs;

public static class APIInteropExt
{
    public static APIInteropTypes.HANDLE<T> Increment<T>(this APIInteropTypes.HANDLE<T> handle) where T : notnull
    {
        IntPtr updatedHandleAddress =  (IntPtr)(handle.PtrLocation.ToInt64() + IntPtr.Size);
        return new APIInteropTypes.HANDLE<T>(updatedHandleAddress);
    }
    
    public static APIInteropTypes.HANDLE Increment(this APIInteropTypes.HANDLE handle)
    {
        IntPtr updatedHandleAddress =  (IntPtr)(handle.PtrLocation.ToInt64() + IntPtr.Size);
        return new APIInteropTypes.HANDLE(updatedHandleAddress);
    }
    
    public static APIInteropTypes.HANDLE<T> IncrementBy<T>(this APIInteropTypes.HANDLE<T> handle, int increment) where T : notnull
    {
        IntPtr updatedHandleAddress =  (IntPtr)(handle.PtrLocation.ToInt64() + increment);
        return new APIInteropTypes.HANDLE<T>(updatedHandleAddress);
    }
    
    public static APIInteropTypes.HANDLE IncrementBy(this APIInteropTypes.HANDLE handle, int increment)
    {
        IntPtr updatedHandleAddress =  (IntPtr)(handle.PtrLocation.ToInt64() + increment);
        return new APIInteropTypes.HANDLE(updatedHandleAddress);
    }
}