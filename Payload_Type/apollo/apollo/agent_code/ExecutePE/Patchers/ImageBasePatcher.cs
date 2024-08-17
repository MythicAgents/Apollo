using System;
using System.Runtime.InteropServices;
using ApolloInterop.Utils;
using ExecutePE.Helpers;

namespace ExecutePE.Patchers
{
    internal class ImageBasePatcher
    {
        private const int IMAGE_BASE_ADDRESS_PEB_OFFSET = 0x10;

        private IntPtr _originalBaseAddress;
        private IntPtr _PEBImageBaseAddress;

        private IntPtr _newProcessBaseAddress;

        public ImageBasePatcher(IntPtr newProcessBase)
        {
            _newProcessBaseAddress = newProcessBase;
        }

        public bool PatchImageBaseAddress()
        {
            var pebAddress = Utils.GetPointerToPeb();
            _PEBImageBaseAddress = pebAddress.Add(IMAGE_BASE_ADDRESS_PEB_OFFSET);
            _originalBaseAddress = Marshal.ReadIntPtr(_PEBImageBaseAddress);

            try
            {
                Marshal.WriteIntPtr(_PEBImageBaseAddress, _newProcessBaseAddress);
            }
            catch (AccessViolationException)
            {
                return false;
            }

            return true;
        }

        internal bool RevertImageBasePatch()
        {
            try
            {
                Marshal.WriteIntPtr(_PEBImageBaseAddress, _originalBaseAddress);
            }
            catch (AccessViolationException)
            {
                return false;
            }

            return true;
        }
    }
}
