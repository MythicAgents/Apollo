using System;
using System.Runtime.InteropServices;
using ExecutePE.Helpers;

namespace ExecutePE.Patchers
{
    internal class ExtraEnvironmentPatcher
    {
        private const int PEB_BASE_ADDRESS_OFFSET = 0x10;

        private IntPtr _pOriginalPebBaseAddress;
        private IntPtr _pPEBBaseAddr;

        private IntPtr _newPEBaseAddress;

        public ExtraEnvironmentPatcher(IntPtr newPEBaseAddress)
        {
            _newPEBaseAddress = newPEBaseAddress;
        }

        internal bool PerformExtraEnvironmentPatches()
        {
#if DEBUG


#endif
            return PatchPebBaseAddress();
        }

        private bool PatchPebBaseAddress()
        {
#if DEBUG


#endif
            _pPEBBaseAddr = (IntPtr)(Utils.GetPointerToPeb().ToInt64() + PEB_BASE_ADDRESS_OFFSET);
#if DEBUG


#endif
            _pOriginalPebBaseAddress = Marshal.ReadIntPtr(_pPEBBaseAddr);
#if DEBUG


#endif
            if (!Utils.PatchAddress(_pPEBBaseAddr, _newPEBaseAddress))
            {
#if DEBUG


#endif
                return false;
            }
#if DEBUG
            var pNewPebBaseAddress = Marshal.ReadIntPtr(_pPEBBaseAddr);


#endif
            return true;
        }

        internal bool RevertExtraPatches()
        {
#if DEBUG


#endif
            if (!Utils.PatchAddress(_pPEBBaseAddr, _pOriginalPebBaseAddress))
            {
#if DEBUG


#endif
                return false;
            }
#if DEBUG


#endif
            return true;
        }
    }
}