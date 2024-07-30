using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using ExecutePE.Helpers;

namespace ExecutePE.Patchers
{
    internal class ArgumentHandler
    {
        private const int
            PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET =
                0x20; // Offset into the PEB that the RTL_USER_PROCESS_PARAMETERS pointer sits at

        private const int
            RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET =
                0x70; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters

        private const int RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET = 2;

        private const int
            RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET =
                0x60; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters

        private const int
            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET =
                0x8; // Offset into the UNICODE_STRING struct that the string pointer sits at https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string

        private byte[]? _originalCommandLineFuncBytes;
        private IntPtr _ppCommandLineString;
        private IntPtr _ppImageString;
        private IntPtr _pLength;
        private IntPtr _pMaxLength;
        private IntPtr _pOriginalCommandLineString;
        private IntPtr _pOriginalImageString;
        private IntPtr _pNewString;
        private short _originalLength;
        private short _originalMaxLength;
        private string? _commandLineFunc;
        private Encoding _encoding = Encoding.UTF8;

        public bool UpdateArgs(string imageName, string commandLine)
        {
            var pPEB = Utils.GetPointerToPeb();
            if (pPEB == IntPtr.Zero)
            {
                return false;
            }

            GetPebCommandLineAndImagePointers(pPEB, out _ppCommandLineString, out _pOriginalCommandLineString,
                out _ppImageString, out _pOriginalImageString, out _pLength, out _originalLength, out _pMaxLength,
                out _originalMaxLength);

            var pNewCommandLineString = Marshal.StringToHGlobalUni(commandLine);
            var pNewImageString = Marshal.StringToHGlobalUni(imageName);
            if (!Utils.PatchAddress(_ppCommandLineString, pNewCommandLineString))
            {

                return false;
            }
            if (!Utils.PatchAddress(_ppImageString, pNewImageString))
            {
                return false;
            }
            Marshal.WriteInt16(_pLength, 0, (short)commandLine.Length);
            Marshal.WriteInt16(_pMaxLength, 0, (short)commandLine.Length);

            if (!PatchGetCommandLineFunc(commandLine))
            {
                return false;
            }

            return true;
        }

        private bool PatchGetCommandLineFunc(string commandLine)
        {
            var pCommandLineString = NativeDeclarations.GetCommandLine();
            var commandLineString = Marshal.PtrToStringAuto(pCommandLineString);

            if (commandLineString != null)
            {
                var stringBytes = new byte[commandLineString.Length];

                // Copy the command line string bytes into an array and check if it contains null bytes (so if it is wide or not
                Marshal.Copy(pCommandLineString, stringBytes, 0,
                    commandLineString.Length); // Even if ASCII won't include null terminating byte

                if (!new List<byte>(stringBytes).Contains(0x00))
                {
                    _encoding = Encoding.ASCII; // At present assuming either ASCII or UTF8
                }

                PERunner.encoding = _encoding;
            }

            // Set the GetCommandLine func based on the determined encoding
            _commandLineFunc = _encoding.Equals(Encoding.ASCII) ? "GetCommandLineA" : "GetCommandLineW";

            // Write the new command line string into memory
            _pNewString = _encoding.Equals(Encoding.ASCII)
                ? Marshal.StringToHGlobalAnsi(commandLine)
                : Marshal.StringToHGlobalUni(commandLine);

            // Create the patch bytes that provide the new string pointer
            var patchBytes = new List<byte>() { 0x48, 0xB8 }; // TODO architecture
            var pointerBytes = BitConverter.GetBytes(_pNewString.ToInt64());

            patchBytes.AddRange(pointerBytes);

            patchBytes.Add(0xC3);

            // Patch the GetCommandLine function to return the new string
            _originalCommandLineFuncBytes = Utils.PatchFunction("kernelbase", _commandLineFunc, patchBytes.ToArray());
            if (_originalCommandLineFuncBytes == null)
            {
                return false;
            }

            return true;
        }

        private static void GetPebCommandLineAndImagePointers(IntPtr pPEB, out IntPtr ppCommandLineString,
            out IntPtr pCommandLineString, out IntPtr ppImageString, out IntPtr pImageString,
            out IntPtr pCommandLineLength, out short commandLineLength, out IntPtr pCommandLineMaxLength,
            out short commandLineMaxLength)
        {
            var ppRtlUserProcessParams = (IntPtr)(pPEB.ToInt64() + PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET);
            var pRtlUserProcessParams = Marshal.ReadInt64(ppRtlUserProcessParams);
            ppCommandLineString = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                  UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pCommandLineString = (IntPtr)Marshal.ReadInt64(ppCommandLineString);

            ppImageString = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET +
                            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pImageString = (IntPtr)Marshal.ReadInt64(ppImageString);

            pCommandLineLength = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET;
            commandLineLength = Marshal.ReadInt16(pCommandLineLength);

            pCommandLineMaxLength = (IntPtr)pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                    RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET;
            commandLineMaxLength = Marshal.ReadInt16(pCommandLineMaxLength);
        }

        internal void ResetArgs()
        {
            if (_originalCommandLineFuncBytes is not null && _commandLineFunc is not null)
            {
                Utils.PatchFunction("kernelbase", _commandLineFunc, _originalCommandLineFuncBytes);
            }

            Utils.PatchAddress(_ppCommandLineString, _pOriginalCommandLineString);
            Utils.PatchAddress(_ppImageString, _pOriginalImageString);

            Marshal.WriteInt16(_pLength, 0, _originalLength);
            Marshal.WriteInt16(_pMaxLength, 0, _originalMaxLength);
        }
    }
}
