using System;
using System.Runtime.InteropServices;

namespace ApolloInterop.Features.WindowsTypesAndAPIs;

public class APIInteropTypes
{
    
    /// <summary>
    /// A windows NT status code
    /// </summary>
    public readonly record struct NTSTATUS
    {
        
        public readonly Ntstatus Status;
        public static readonly NTSTATUS STATUS_SUCCESS = (NTSTATUS)0;
        public Severity SeverityCode => (Severity)(((uint)Status & 0xc0000000) >> 30);

        public NTSTATUS(int status) => Status = (Ntstatus)status;

        
        public static implicit operator int(NTSTATUS value) => (int)value.Status;
        public static explicit operator NTSTATUS(int value) => new(value);
        public static implicit operator uint(NTSTATUS value) => (uint)value.Status;
        public static explicit operator NTSTATUS(uint value) => new((int)value);
    }
    
    
    /// <summary>
    /// A pointer to an object
    /// Can be used in P/Invoke calls to pass a pointer to a structure or object
    /// </summary>
    /// <param name="value"></param>
    [StructLayout(LayoutKind.Sequential)]
    public readonly record struct HANDLE
    {
        public readonly IntPtr PtrLocation;
        public static HANDLE Null => (HANDLE)IntPtr.Zero;
        public bool IsNull => PtrLocation == default;

        
        public static long operator -(HANDLE value1, HANDLE value2) => value1.PtrLocation.ToInt64() - value2.PtrLocation.ToInt64();
        
        public static implicit operator IntPtr(HANDLE value) => value.PtrLocation;
        public static explicit operator HANDLE(IntPtr value) => new(value);
        
        public T CastTo<T>() where T : notnull => (T)Marshal.PtrToStructure(PtrLocation, typeof(T));
        
        public HANDLE(IntPtr value) => PtrLocation = value;
    }
    
    /// <summary>
    /// A version of the handle struct that takes in a generic argument this is used to specify the type of the handle mainly for easier debugging, and readability
    /// Note the GetValue method will only work on types that are Structs, classes and are non value types
    /// </summary>
    /// <param name="value"></param>
    /// <typeparam name="T"></typeparam>
    [StructLayout(LayoutKind.Sequential)]
    public readonly record struct HANDLE<T> where T : notnull
    {
        //fields & properties
        public readonly IntPtr PtrLocation { get; init; }
        public static HANDLE<T> Null => (HANDLE<T>)IntPtr.Zero;
        public string HandleTypeName => typeof(T).Name;
        public bool IsNull => PtrLocation == default;

        //methods
        public T? GetValue() => (T)Marshal.PtrToStructure(PtrLocation, typeof(T));
        

       
        public static long operator -(HANDLE<T> value1, HANDLE<T> value2) => value1.PtrLocation.ToInt64() - value2.PtrLocation.ToInt64();
        public static implicit operator IntPtr(HANDLE<T> value) => value.PtrLocation;
        public static explicit operator HANDLE<T>(IntPtr value) => new(value);
        public static implicit operator HANDLE(HANDLE<T> value) => new(value.PtrLocation);
        public static explicit operator HANDLE<T>(HANDLE value) => new(value.PtrLocation);
        
        //constructors
        public HANDLE(IntPtr value)  => PtrLocation = value;
        
        public HANDLE(T value)
        {
            PtrLocation = Marshal.AllocHGlobal(Marshal.SizeOf(value));
            Marshal.StructureToPtr(value, PtrLocation, false);
        }

    }
    
    
    public readonly record struct UCHAR
    {
        public readonly byte Value;
        public static implicit operator byte(UCHAR value) => value.Value;
        public static explicit operator UCHAR(byte value) => new(value);
        
        public UCHAR(byte value) => Value = value;
        public UCHAR (char value) => Value = (byte)value;
    }
    
    
}