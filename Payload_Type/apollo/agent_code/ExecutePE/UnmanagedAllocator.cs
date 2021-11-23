using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExecutePE
{
    public enum UnmanagedAllocationResult
    {
        Success,
        Failure,
        AlreadyAllocated,
        ArgOk
    }

    public interface IUnmanagedAllocator
    {
        UnmanagedAllocationResult Allocate(ref PEMapInfo mapInfo);
    }

    public abstract class UnmanagedAllocator : IUnmanagedAllocator
    {
        public virtual UnmanagedAllocationResult CheckArgs(PEMapInfo mapInfo)
        {
            if (mapInfo.AllocatedImageBase != IntPtr.Zero)
            {
                return UnmanagedAllocationResult.AlreadyAllocated;
            }

            if (mapInfo.SizeOfImage <= 0)
            {
                return UnmanagedAllocationResult.Failure;
            }

            return UnmanagedAllocationResult.ArgOk;
        }

        public abstract UnmanagedAllocationResult Allocate(ref PEMapInfo mapInfo);
    }
}
