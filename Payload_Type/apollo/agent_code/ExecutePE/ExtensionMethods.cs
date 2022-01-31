using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExecutePE
{
    public static class ExtensionMethods
    {
        public static IntPtr Inc(this IntPtr ptr)
        {
            return IntPtr.Add(ptr, 1);
        }

        public static IntPtr Dec(this IntPtr ptr)
        {
            return IntPtr.Subtract(ptr, 1);
        }

        public static unsafe IntPtr Add(this IntPtr ptr, IntPtr offset)
        {
            if (IntPtr.Size == 4)
            {
                return new IntPtr((byte*)ptr + (uint)offset);
            }

            if (IntPtr.Size == 8)
            {
                return new IntPtr((byte*)ptr + (ulong)offset);
            }

            throw new NotSupportedException();
        }

        public static unsafe IntPtr Add(this IntPtr ptr, ulong offset)
        {
            return new IntPtr((byte*)ptr + offset);
        }

        public static IntPtr Add(this IntPtr ptr, int offset)
        {
            unsafe
            {
                return new IntPtr((byte*)ptr + offset);
            }
        }

        public static IntPtr Add(this IntPtr ptr, uint offset)
        {
            unsafe
            {
                return new IntPtr((byte*)ptr + offset);
            }
        }

        public static IntPtr Add(this IntPtr ptr, params int[] offsets)
        {
            return Add(ptr, offsets.Sum());
        }
        public static unsafe IntPtr Sub(this IntPtr ptr, IntPtr offset)
        {
            if (IntPtr.Size == 4)
            {
                return new IntPtr((byte*)ptr - (uint)offset);
            }

            if (IntPtr.Size == 8)
            {
                return new IntPtr((byte*)ptr + (ulong)offset);
            }

            throw new NotSupportedException();
        }

        public static unsafe IntPtr Sub(this IntPtr ptr, ulong offset)
        {
            return new IntPtr((byte*)ptr - offset);
        }
    }
}
