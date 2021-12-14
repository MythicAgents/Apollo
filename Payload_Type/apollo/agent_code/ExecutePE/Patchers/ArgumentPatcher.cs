using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using ExecutePE.Helpers;
using ExecutePE.Internals;

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

        private byte[] _originalCommandLineFuncBytes;
        private IntPtr _ppCommandLineString;
        private IntPtr _ppImageString;
        private IntPtr _pLength;
        private IntPtr _pMaxLength;
        private IntPtr _pOriginalCommandLineString;
        private IntPtr _pOriginalImageString;
        private IntPtr _pNewString;
        private short _originalLength;
        private short _originalMaxLength;
        private string _commandLineFunc = null;
        private Encoding _encoding;

        public bool UpdateArgs(string filename, string[] args)
        {
            var pPEB = Utils.GetPointerToPeb();
            if (pPEB == IntPtr.Zero)
            {
                return false;
            }

            GetPebCommandLineAndImagePointers(pPEB, out _ppCommandLineString, out _pOriginalCommandLineString,
                out _ppImageString, out _pOriginalImageString, out _pLength, out _originalLength, out _pMaxLength,
                out _originalMaxLength);

            var commandLineString = Marshal.PtrToStringUni(_pOriginalCommandLineString);
            var imageString = Marshal.PtrToStringUni(_pOriginalImageString);
            var newCommandLineString = $"\"{filename}\" {string.Join(" ", args)}";
            var pNewCommandLineString = Marshal.StringToHGlobalUni(newCommandLineString);
            var pNewImageString = Marshal.StringToHGlobalUni(filename);
            if (!Utils.PatchAddress(_ppCommandLineString, pNewCommandLineString))
            {

                return false;
            }
#if DEBUG


#endif
            if (!Utils.PatchAddress(_ppImageString, pNewImageString))
            {
#if DEBUG


#endif
                return false;
            }
#if DEBUG


#endif
            Marshal.WriteInt16(_pLength, 0, (short)newCommandLineString.Length);
#if DEBUG


#endif
            Marshal.WriteInt16(_pMaxLength, 0, (short)newCommandLineString.Length);

#if DEBUG
            GetPebCommandLineAndImagePointers(pPEB, out _, out var pCommandLineStringCheck, out _,
                out var pImageStringCheck, out _, out var lengthCheck, out _, out var maxLengthCheck);
            var commandLineStringCheck = Marshal.PtrToStringUni(pCommandLineStringCheck);


            var imageStringCheck = Marshal.PtrToStringUni(pImageStringCheck);










#endif

            if (!PatchGetCommandLineFunc(newCommandLineString))
            {
                return false;
            }

#if DEBUG
            var getCommandLineAPIString = Marshal.PtrToStringUni(NativeDeclarations.GetCommandLine());



#endif
            return true;
        }

        private bool PatchGetCommandLineFunc(string newCommandLineString)
        {
            var pCommandLineString = NativeDeclarations.GetCommandLine();
            var commandLineString = Marshal.PtrToStringAuto(pCommandLineString);

            _encoding = Encoding.UTF8;

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

                Program.encoding = _encoding;

#if DEBUG
                // Print the string bytes and what the encoding was determined to be
                var stringBytesHexString = "";
                foreach (var x in stringBytes)
                {
                    stringBytesHexString += x.ToString("X") + " ";
                }





#endif
            }

            // Set the GetCommandLine func based on the determined encoding
            _commandLineFunc = _encoding.Equals(Encoding.ASCII) ? "GetCommandLineA" : "GetCommandLineW";

#if DEBUG


#endif
            // Write the new command line string into memory
            _pNewString = _encoding.Equals(Encoding.ASCII)
                ? Marshal.StringToHGlobalAnsi(newCommandLineString)
                : Marshal.StringToHGlobalUni(newCommandLineString);
#if DEBUG


#endif
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

#if DEBUG
            var pNewCommandLineString = NativeDeclarations.GetCommandLine();


#endif
            return true;
        }

        private static void GetPebCommandLineAndImagePointers(IntPtr pPEB, out IntPtr ppCommandLineString,
            out IntPtr pCommandLineString, out IntPtr ppImageString, out IntPtr pImageString,
            out IntPtr pCommandLineLength, out short commandLineLength, out IntPtr pCommandLineMaxLength,
            out short commandLineMaxLength)
        {
#if DEBUG


#endif
            var ppRtlUserProcessParams = (IntPtr)(pPEB.ToInt64() + PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET);
#if DEBUG


#endif
            var pRtlUserProcessParams = Marshal.ReadInt64(ppRtlUserProcessParams);
#if DEBUG


#endif
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
#if DEBUG
















#endif
        }

        internal void ResetArgs()
        {
#if DEBUG


#endif
            if (Utils.PatchFunction("kernelbase", _commandLineFunc, _originalCommandLineFuncBytes) == null)
            {
#if DEBUG


#endif
            }
#if DEBUG


#endif
            if (!Utils.PatchAddress(_ppCommandLineString, _pOriginalCommandLineString))
            {
#if DEBUG


#endif
            }
#if DEBUG


#endif
            if (!Utils.PatchAddress(_ppImageString, _pOriginalImageString))
            {
#if DEBUG


#endif
            }
#if DEBUG


#endif
            Marshal.WriteInt16(_pLength, 0, _originalLength);
#if DEBUG


#endif
            Marshal.WriteInt16(_pMaxLength, 0, _originalMaxLength);
#if DEBUG


#endif
        }
    }
}