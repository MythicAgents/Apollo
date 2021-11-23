using System;
using System.Runtime.InteropServices;

namespace ExecutePE
{
    public class VirtualAllocAllocator : UnmanagedAllocator
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

        public override UnmanagedAllocationResult Allocate(ref PEMapInfo mapInfo)
        {
            var status = base.CheckArgs(mapInfo);

            if (status == UnmanagedAllocationResult.ArgOk)
            {
                var ptr = VirtualAlloc(mapInfo.RequestedImageBase, (IntPtr)mapInfo.SizeOfImage, 0x3000, 0x04);

                if (ptr == IntPtr.Zero)
                {
                    mapInfo.WasAllocatedAtRequestedBase = false;

                    ptr = VirtualAlloc(IntPtr.Zero, (IntPtr)mapInfo.SizeOfImage, 0x3000, 0x04);
                }

                if (ptr != IntPtr.Zero)
                {
                    mapInfo.AllocatedImageBase = ptr;
                    mapInfo.WasAllocatedAtRequestedBase = true;
                    status = UnmanagedAllocationResult.Success;
                }
            }

            return status;
        }
    }
}
