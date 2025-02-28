using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ExecutePE;

public static class PERunner
{
    internal static Encoding encoding = Encoding.UTF8;

    /// <summary>
    /// Provides functionality to hook the GetCommandLine API functions.
    /// This ensures that calls to GetCommandLineA and GetCommandLineW from the in-memory PE
    /// will return our custom command line instead of the process's actual command line.
    /// </summary>
    public class CommandLineHooking : IDisposable
    {
        #region Native Methods and Structures

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetCommandLineW();

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetCommandLineA();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                                uint flNewProtect, out uint lpflOldProtect);

        // Memory protection constants
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;

        // x86 and x64 hook structures and constants
        private const int X86_JMP_SIZE = 5;  // 5 bytes: E9 + 32-bit offset
        private const int X64_JMP_SIZE = 14; // 14 bytes: FF 25 00 00 00 00 + 64-bit absolute address

        #endregion

        #region Fields

        // Original function pointers
        private IntPtr _originalGetCommandLineW;
        private IntPtr _originalGetCommandLineA;

        // Hook function delegates (must be kept alive to prevent garbage collection)
        private GetCommandLineWDelegate _getCommandLineWHook;
        private GetCommandLineADelegate _getCommandLineAHook;

        // Custom command lines
        private string _commandLineW;
        private string _commandLineA;

        // Memory for storing the custom command lines
        private GCHandle _commandLineWHandle;
        private GCHandle _commandLineAHandle;
        private IntPtr _commandLineWPtr;
        private IntPtr _commandLineAPtr;

        // Original bytes at each hook location (for restoring)
        private byte[] _originalGetCommandLineWBytes;
        private byte[] _originalGetCommandLineABytes;

        // State tracking
        private bool _disposed;
        private bool _hooksApplied;
        private bool _is64Bit;

        #endregion

        #region Delegates

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private delegate IntPtr GetCommandLineWDelegate();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private delegate IntPtr GetCommandLineADelegate();

        #endregion

        #region Constructor and Finalizer

        /// <summary>
        /// Initializes a new instance of the CommandLineHooking class.
        /// </summary>
        /// <param name="commandLine">The custom command line to provide to the PE.</param>
        /// <param name="is64Bit">True if the PE file is 64-bit, false otherwise.</param>
        public CommandLineHooking(string commandLine, bool is64Bit)
        {
            if (string.IsNullOrEmpty(commandLine))
                throw new ArgumentNullException(nameof(commandLine));

            _is64Bit = is64Bit;

            // Prepare the Unicode (wide) command line
            _commandLineW = EnsureNullTerminated(commandLine);

            // Prepare the ANSI command line
            // Note: This is a simple conversion to ANSI and might not handle all character encodings correctly
            _commandLineA = EnsureNullTerminated(commandLine);

            // Create delegates for our hook functions
            _getCommandLineWHook = new GetCommandLineWDelegate(HookGetCommandLineW);
            _getCommandLineAHook = new GetCommandLineADelegate(HookGetCommandLineA);
        }

        ~CommandLineHooking()
        {
            Dispose(false);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Applies hooks to the GetCommandLine API functions.
        /// </summary>
        public void ApplyHooks()
        {
            if (_hooksApplied)
                return;

            try
            {
                // Find the original function addresses
                IntPtr kernel32 = GetModuleHandle("kernel32.dll");
                if (kernel32 == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to get handle to kernel32.dll");

                _originalGetCommandLineW = GetProcAddress(kernel32, "GetCommandLineW");
                _originalGetCommandLineA = GetProcAddress(kernel32, "GetCommandLineA");

                if (_originalGetCommandLineW == IntPtr.Zero || _originalGetCommandLineA == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to get address of GetCommandLine functions");

                // Allocate memory for custom command lines and pin it
                _commandLineWHandle = GCHandle.Alloc(_commandLineW, GCHandleType.Pinned);
                _commandLineAHandle = GCHandle.Alloc(_commandLineA, GCHandleType.Pinned);
                _commandLineWPtr = _commandLineWHandle.AddrOfPinnedObject();
                _commandLineAPtr = _commandLineAHandle.AddrOfPinnedObject();

                // Apply hooks to the API functions
                ApplyFunctionHook(_originalGetCommandLineW,
                                  Marshal.GetFunctionPointerForDelegate(_getCommandLineWHook),
                                  out _originalGetCommandLineWBytes);

                ApplyFunctionHook(_originalGetCommandLineA,
                                  Marshal.GetFunctionPointerForDelegate(_getCommandLineAHook),
                                  out _originalGetCommandLineABytes);

                _hooksApplied = true;
            }
            catch (Exception ex)
            {
                // Attempt to undo any partial changes
                try
                {
                    RemoveHooks();
                }
                catch
                {
                    // Best effort cleanup
                }

                throw new InvalidOperationException("Failed to apply GetCommandLine API hooks", ex);
            }
        }

        /// <summary>
        /// Removes the applied hooks and restores original functionality.
        /// </summary>
        public void RemoveHooks()
        {
            if (!_hooksApplied)
                return;

            // Restore original bytes for the GetCommandLineW function
            if (_originalGetCommandLineW != IntPtr.Zero && _originalGetCommandLineWBytes != null)
            {
                RestoreOriginalBytes(_originalGetCommandLineW, _originalGetCommandLineWBytes);
            }

            // Restore original bytes for the GetCommandLineA function
            if (_originalGetCommandLineA != IntPtr.Zero && _originalGetCommandLineABytes != null)
            {
                RestoreOriginalBytes(_originalGetCommandLineA, _originalGetCommandLineABytes);
            }

            // Free the pinned command line strings
            if (_commandLineWHandle.IsAllocated)
                _commandLineWHandle.Free();

            if (_commandLineAHandle.IsAllocated)
                _commandLineAHandle.Free();

            _commandLineWPtr = IntPtr.Zero;
            _commandLineAPtr = IntPtr.Zero;

            _hooksApplied = false;
        }

        #endregion

        #region Private Methods

        // Our hook implementation of GetCommandLineW
        private IntPtr HookGetCommandLineW()
        {
            // Simply return a pointer to our custom Unicode command line
            return _commandLineWPtr;
        }

        // Our hook implementation of GetCommandLineA
        private IntPtr HookGetCommandLineA()
        {
            // Simply return a pointer to our custom ANSI command line
            return _commandLineAPtr;
        }

        private void ApplyFunctionHook(IntPtr targetFunction, IntPtr hookFunction, out byte[] originalBytes)
        {
            if (targetFunction == IntPtr.Zero || hookFunction == IntPtr.Zero)
            {
                originalBytes = null;
                return;
            }

            // Determine the hook size and format based on architecture
            int hookSize = _is64Bit ? X64_JMP_SIZE : X86_JMP_SIZE;

            // Save the original bytes for later restoration
            originalBytes = new byte[hookSize];
            Marshal.Copy(targetFunction, originalBytes, 0, hookSize);

            // Create the hook bytes
            byte[] hookBytes;

            if (_is64Bit)
            {
                // In x64, we use a slightly more complex sequence:
                // FF 25 00 00 00 00 [8-byte absolute address]
                // This is a JMP [RIP+0] instruction followed by the absolute address
                hookBytes = new byte[X64_JMP_SIZE];
                hookBytes[0] = 0xFF;  // JMP opcode
                hookBytes[1] = 0x25;  // ModR/M byte for JMP [RIP+disp32]
                hookBytes[2] = 0x00;  // 32-bit displacement = 0
                hookBytes[3] = 0x00;
                hookBytes[4] = 0x00;
                hookBytes[5] = 0x00;

                // Absolute address of our hook function
                BitConverter.GetBytes(hookFunction.ToInt64()).CopyTo(hookBytes, 6);
            }
            else
            {
                // In x86, we use a simpler JMP rel32 instruction:
                // E9 [4-byte relative address]
                hookBytes = new byte[X86_JMP_SIZE];
                hookBytes[0] = 0xE9;  // JMP opcode

                // Calculate relative address (hook - target - 5)
                int relativeAddress = hookFunction.ToInt32() - targetFunction.ToInt32() - 5;
                BitConverter.GetBytes(relativeAddress).CopyTo(hookBytes, 1);
            }

            // Make the memory writable
            uint oldProtect;
            VirtualProtect(targetFunction, (UIntPtr)hookSize, PAGE_EXECUTE_READWRITE, out oldProtect);

            try
            {
                // Write the hook
                Marshal.Copy(hookBytes, 0, targetFunction, hookSize);
            }
            finally
            {
                // Restore the original protection
                VirtualProtect(targetFunction, (UIntPtr)hookSize, oldProtect, out _);
            }
        }

        private void RestoreOriginalBytes(IntPtr address, byte[] originalBytes)
        {
            if (address == IntPtr.Zero || originalBytes == null || originalBytes.Length == 0)
                return;

            // Make the memory writable
            uint oldProtect;
            VirtualProtect(address, (UIntPtr)originalBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect);

            try
            {
                // Restore the original bytes
                Marshal.Copy(originalBytes, 0, address, originalBytes.Length);
            }
            finally
            {
                // Restore the original protection
                VirtualProtect(address, (UIntPtr)originalBytes.Length, oldProtect, out _);
            }
        }

        private string EnsureNullTerminated(string str)
        {
            // Ensure the string ends with a null terminator
            if (str == null)
                return "\0";

            return str.EndsWith("\0") ? str : str + "\0";
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes resources used by the CommandLineHooking instance.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                }

                // Clean up unmanaged resources
                try
                {
                    RemoveHooks();
                }
                catch
                {
                    // Best effort cleanup
                }

                _disposed = true;
            }
        }

        #endregion
    }
    public class ExitInterceptor : IDisposable
    {
        // Native functions
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                                uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        // Constants
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        // Delegate for the original function
        private delegate int TerminateProcessDelegate(IntPtr hProcess, uint exitCode);

        // Track patched functions
        private Dictionary<string, Dictionary<string, byte[]>> _originalBytes =
            new Dictionary<string, Dictionary<string, byte[]>>();

        /// <summary>
        /// Cleans up resources used by the exit interceptor.
        /// This does NOT restore the original functions - by design, since that can cause issues.
        /// </summary>
        public void Dispose()
        {
            return;
        }

        /// <summary>
        /// Applies patches to prevent process exit functions from terminating the process.
        /// </summary>
        /// <returns>True if all critical patches were applied successfully.</returns>
        public bool ApplyExitFunctionPatches()
        {
            //Console.WriteLine("Applying exit function patches...");

            // Dictionary to track module handles
            Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

            // Dictionary to track functions to patch
            Dictionary<string, Dictionary<string, IntPtr>> functionsToPatch = new Dictionary<string, Dictionary<string, IntPtr>>();

            try
            {
                // Initialize modules
                modules["kernel32"] = GetModuleHandle("kernel32.dll");
                modules["kernelbase"] = GetModuleHandle("kernelbase.dll");
                modules["ntdll"] = GetModuleHandle("ntdll.dll");

                // Try to get mscoree (optional - only needed for .NET processes)
                modules["mscoree"] = GetModuleHandle("mscoree.dll");

                // Validate critical modules
                if (modules["kernelbase"] == IntPtr.Zero && modules["kernel32"] == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get handle to kernelbase.dll or kernel32.dll");
                    return false;
                }

                if (modules["ntdll"] == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get handle to ntdll.dll");
                    return false;
                }

                // Initialize function collections
                foreach (var module in modules.Keys)
                {
                    functionsToPatch[module] = new Dictionary<string, IntPtr>();
                }

                // Find exit functions in kernelbase (preferred) or kernel32
                IntPtr baseModule = modules["kernelbase"] != IntPtr.Zero ? modules["kernelbase"] : modules["kernel32"];
                string baseModuleName = modules["kernelbase"] != IntPtr.Zero ? "kernelbase" : "kernel32";

                // Get function addresses
                functionsToPatch[baseModuleName]["TerminateProcess"] = GetProcAddress(baseModule, "TerminateProcess");
                functionsToPatch[baseModuleName]["ExitProcess"] = GetProcAddress(baseModule, "ExitProcess");

                // Get ntdll functions
                functionsToPatch["ntdll"]["NtTerminateProcess"] = GetProcAddress(modules["ntdll"], "NtTerminateProcess");
                functionsToPatch["ntdll"]["RtlExitUserProcess"] = GetProcAddress(modules["ntdll"], "RtlExitUserProcess");
                functionsToPatch["ntdll"]["ZwTerminateProcess"] = GetProcAddress(modules["ntdll"], "ZwTerminateProcess");

                // Check if mscoree is loaded, and if so, get CorExitProcess
                if (modules["mscoree"] != IntPtr.Zero)
                {
                    functionsToPatch["mscoree"]["CorExitProcess"] = GetProcAddress(modules["mscoree"], "CorExitProcess");
                }

                // Get ExitThread function to use in our redirection
                IntPtr exitThreadAddr = GetProcAddress(baseModule, "ExitThread");
                if (exitThreadAddr == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get address of ExitThread function");
                    return false;
                }

                // Validate critical functions
                if (functionsToPatch[baseModuleName]["TerminateProcess"] == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get address of TerminateProcess");
                    return false;
                }

                if (functionsToPatch["ntdll"]["NtTerminateProcess"] == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get address of NtTerminateProcess");
                    return false;
                }

                // Track success status
                bool allCriticalPatchesSucceeded = true;
                int patchedCount = 0;

                // Create exit thread redirection bytes for function patching
                byte[] redirectToExitThread = CreateExitThreadRedirection(exitThreadAddr);

                // Apply patches to all functions
                foreach (var moduleName in functionsToPatch.Keys)
                {
                    foreach (var functionName in functionsToPatch[moduleName].Keys)
                    {
                        IntPtr functionAddr = functionsToPatch[moduleName][functionName];
                        if (functionAddr != IntPtr.Zero)
                        {
                            bool isCritical = IsCriticalExitFunction(moduleName, functionName);
                            bool success = PatchFunction(moduleName, functionName, functionAddr, redirectToExitThread);

                            if (success)
                            {
                                patchedCount++;
                                //Console.WriteLine($"Successfully patched {moduleName}.{functionName}");
                            }
                            else
                            {
                                Console.WriteLine($"Failed to patch {moduleName}.{functionName}");
                                if (isCritical)
                                {
                                    allCriticalPatchesSucceeded = false;
                                }
                            }
                        }
                    }
                }

                //Console.WriteLine($"Exit function patching complete. Successfully patched {patchedCount} functions.");
                return allCriticalPatchesSucceeded;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error applying exit function patches: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Creates a small assembly stub that redirects a process exit function to ExitThread.
        /// </summary>
        /// <param name="exitThreadAddr">Address of the ExitThread function.</param>
        /// <returns>Byte array containing the redirection code.</returns>
        private byte[] CreateExitThreadRedirection(IntPtr exitThreadAddr)
        {
            // Create redirection that preserves the exit code parameter
            byte[] redirection = new byte[] {
        0x48, 0x89, 0xC8,          // mov rax, rcx (preserve exit code)
        0x48, 0x31, 0xC9,          // xor rcx, rcx (zero out rcx)
        0x48, 0x89, 0xC1,          // mov rcx, rax (restore exit code to first param)
        0x48, 0xB8                 // mov rax, [ExitThread address]
    };

            // Append the ExitThread address
            byte[] addressBytes = BitConverter.GetBytes(exitThreadAddr.ToInt64());
            byte[] fullRedirection = new byte[redirection.Length + addressBytes.Length + 2];
            Buffer.BlockCopy(redirection, 0, fullRedirection, 0, redirection.Length);
            Buffer.BlockCopy(addressBytes, 0, fullRedirection, redirection.Length, addressBytes.Length);

            // Add the jump
            fullRedirection[redirection.Length + addressBytes.Length] = 0xFF;     // jmp
            fullRedirection[redirection.Length + addressBytes.Length + 1] = 0xE0; // rax

            return fullRedirection;
        }

        /// <summary>
        /// Determines if a function is considered critical for exit prevention.
        /// </summary>
        private bool IsCriticalExitFunction(string moduleName, string functionName)
        {
            // These are the absolutely essential functions to patch
            if ((moduleName == "kernelbase" || moduleName == "kernel32") &&
                (functionName == "TerminateProcess" || functionName == "ExitProcess"))
            {
                return true;
            }

            if (moduleName == "ntdll" &&
                (functionName == "NtTerminateProcess" || functionName == "RtlExitUserProcess"))
            {
                return true;
            }

            // Other functions are helpful but not critical
            return false;
        }

        /// <summary>
        /// Applies a patch to a specific function.
        /// </summary>
        /// <param name="moduleName">Name of the module containing the function.</param>
        /// <param name="functionName">Name of the function to patch.</param>
        /// <param name="functionAddr">Address of the function.</param>
        /// <param name="patchBytes">Bytes to write at the function address.</param>
        /// <returns>True if the patch was applied successfully.</returns>
        private bool PatchFunction(string moduleName, string functionName, IntPtr functionAddr, byte[] patchBytes)
        {
            try
            {
                // Save original bytes for possible restoration
                byte[] originalBytes = new byte[patchBytes.Length];
                Marshal.Copy(functionAddr, originalBytes, 0, originalBytes.Length);

                // Store for cleanup
                if (!_originalBytes.ContainsKey(moduleName))
                {
                    _originalBytes[moduleName] = new Dictionary<string, byte[]>();
                }
                _originalBytes[moduleName][functionName] = originalBytes;

                // Make memory writable
                uint oldProtect;
                if (!VirtualProtect(functionAddr, (UIntPtr)patchBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Console.WriteLine($"Failed to make {moduleName}.{functionName} writable. Error: {GetLastError()}");
                    return false;
                }

                // Write the patch
                Marshal.Copy(patchBytes, 0, functionAddr, patchBytes.Length);

                // Restore protection
                uint ignored;
                VirtualProtect(functionAddr, (UIntPtr)patchBytes.Length, oldProtect, out ignored);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error patching {moduleName}.{functionName}: {ex.Message}");
                return false;
            }
        }
        /// <summary>
        /// Removes all applied patches and restores the original function bytes.
        /// </summary>
        /// <returns>True if all restorations were successful.</returns>
        public bool RemoveExitFunctionPatches()
        {
            //Console.WriteLine("Removing exit function patches...");

            if (_originalBytes == null || _originalBytes.Count == 0)
            {
                Console.WriteLine("No patches to remove.");
                return true;
            }

            bool allRestorationsSuccessful = true;
            int restoredCount = 0;

            try
            {
                // Iterate through modules
                foreach (var moduleName in _originalBytes.Keys)
                {
                    // Get module handle (we'll need it to get function addresses)
                    IntPtr moduleHandle = GetModuleHandle($"{moduleName}.dll");
                    if (moduleHandle == IntPtr.Zero)
                    {
                        Console.WriteLine($"Warning: Could not get handle for {moduleName}.dll");
                        continue;
                    }

                    // Iterate through functions in this module
                    foreach (var functionName in _originalBytes[moduleName].Keys)
                    {
                        // Get the current function address
                        IntPtr functionAddr = GetProcAddress(moduleHandle, functionName);
                        if (functionAddr == IntPtr.Zero)
                        {
                            Console.WriteLine($"Warning: Could not get address for {moduleName}.{functionName}");
                            allRestorationsSuccessful = false;
                            continue;
                        }

                        // Get the original bytes
                        byte[] originalBytes = _originalBytes[moduleName][functionName];

                        // Restore original bytes
                        if (RestoreOriginalBytes(functionAddr, originalBytes, $"{moduleName}.{functionName}"))
                        {
                            restoredCount++;
                        }
                        else
                        {
                            allRestorationsSuccessful = false;
                        }
                    }
                }

                // Clear the tracking dictionary if we successfully restored everything
                if (allRestorationsSuccessful)
                {
                    _originalBytes.Clear();
                }

                //Console.WriteLine($"Exit function patch removal complete. Successfully restored {restoredCount} functions.");
                return allRestorationsSuccessful;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing exit function patches: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Restores the original bytes at a function address.
        /// </summary>
        /// <param name="functionAddr">The address of the function to restore.</param>
        /// <param name="originalBytes">The original bytes to restore.</param>
        /// <param name="functionFullName">The full name of the function (for logging).</param>
        /// <returns>True if restoration was successful.</returns>
        private bool RestoreOriginalBytes(IntPtr functionAddr, byte[] originalBytes, string functionFullName)
        {
            try
            {
                // Make sure we have valid inputs
                if (functionAddr == IntPtr.Zero || originalBytes == null || originalBytes.Length == 0)
                {
                    Console.WriteLine($"Invalid inputs for restoring {functionFullName}");
                    return false;
                }

                // Make memory writable
                uint oldProtect;
                if (!VirtualProtect(functionAddr, (UIntPtr)originalBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Console.WriteLine($"Failed to make {functionFullName} writable for restoration. Error: {GetLastError()}");
                    return false;
                }

                // Write back the original bytes
                Marshal.Copy(originalBytes, 0, functionAddr, originalBytes.Length);

                // Restore protection
                uint ignored;
                VirtualProtect(functionAddr, (UIntPtr)originalBytes.Length, oldProtect, out ignored);

                //Console.WriteLine($"Successfully restored {functionFullName}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error restoring {functionFullName}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// This is a signature for testing the TerminateProcess patch
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    }

    /// <summary>
    /// Loads and executes a PE file directly from memory without writing to disk,
    /// providing command-line customization that makes the PE think it was launched normally.
    /// </summary>
    /// <summary>
    /// Loads and executes a PE file directly from memory without writing to disk,
    /// providing command-line customization that makes the PE think it was launched normally.
    /// </summary>
    public class MemoryPE : IDisposable
    {
        #region Native Methods

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
                                                uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                                 uint flNewProtect, out uint lpflOldProtect);


        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetProcAddress")]
        private static extern IntPtr GetProcAddressByOrdinal(IntPtr hModule, IntPtr lpProcOrdinal);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
                                                 IntPtr lpStartAddress, IntPtr lpParameter,
                                                 uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetCommandLine();

        // These functions help emulate the process environment
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();


        // PEB access requires ntdll structures
        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr ProcessHandle,
                                                          int ProcessInformationClass,
                                                          ref PROCESS_BASIC_INFORMATION ProcessInformation,
                                                          int ProcessInformationLength,
                                                          out int ReturnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate int VectoredExceptionHandler(ref EXCEPTION_POINTERS ExceptionInfo);


        #endregion

        #region Constants
        private const uint EXCEPTION_CONTINUE_EXECUTION = 0;
        private const uint EXCEPTION_CONTINUE_SEARCH = 1;
        private const uint EXCEPTION_BREAKPOINT = 0x80000003;
        // Memory allocation flags
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_RELEASE = 0x8000;

        // Memory protection flags
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOCACHE = 0x200;
        private const uint PAGE_WRITECOMBINE = 0x400;

        // Thread creation flags
        private const uint CREATE_SUSPENDED = 0x4;

        // WaitForSingleObject constants
        private const uint INFINITE = 0xFFFFFFFF;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 0x102;
        private const uint WAIT_FAILED = 0xFFFFFFFF;

        // Standard handle constants
        private const int STD_INPUT_HANDLE = -10;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;

        // Process Information Class
        private const int ProcessBasicInformation = 0;

        // NT_SUCCESS macro equivalent
        private static bool NT_SUCCESS(int status) => status >= 0;

        // PE Header offsets
        private const int PE_HEADER_OFFSET = 0x3C;
        private const int OPTIONAL_HEADER32_MAGIC = 0x10B;
        private const int OPTIONAL_HEADER64_MAGIC = 0x20B;

        // DLL Characteristics
        private const ushort IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040;
        private const ushort IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100;

        // Directory indexes for IMAGE_DATA_DIRECTORY
        private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
        private const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
        private const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
        private const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
        private const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
        private const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
        private const int IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7;
        private const int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
        private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;
        private const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
        private const int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
        private const int IMAGE_DIRECTORY_ENTRY_IAT = 12;
        private const int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
        private const int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

        // Section characteristics
        private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        private const uint IMAGE_SCN_MEM_READ = 0x40000000;
        private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        // Relocation types
        private const int IMAGE_REL_BASED_ABSOLUTE = 0;
        private const int IMAGE_REL_BASED_HIGH = 1;
        private const int IMAGE_REL_BASED_LOW = 2;
        private const int IMAGE_REL_BASED_HIGHLOW = 3;
        private const int IMAGE_REL_BASED_HIGHADJ = 4;
        private const int IMAGE_REL_BASED_DIR64 = 10;

        // Subsystem values
        private const ushort IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
        private const ushort IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;       // Magic number
            public ushort e_cblp;        // Bytes on last page of file
            public ushort e_cp;          // Pages in file
            public ushort e_crlc;        // Relocations
            public ushort e_cparhdr;     // Size of header in paragraphs
            public ushort e_minalloc;    // Minimum extra paragraphs needed
            public ushort e_maxalloc;    // Maximum extra paragraphs needed
            public ushort e_ss;          // Initial (relative) SS value
            public ushort e_sp;          // Initial SP value
            public ushort e_csum;        // Checksum
            public ushort e_ip;          // Initial IP value
            public ushort e_cs;          // Initial (relative) CS value
            public ushort e_lfarlc;      // File address of relocation table
            public ushort e_ovno;        // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1;      // Reserved words
            public ushort e_oemid;       // OEM identifier (for e_oeminfo)
            public ushort e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2;      // Reserved words
            public int e_lfanew;         // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;
            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint PhysicalAddress;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_THUNK_DATA32
        {
            public uint ForwarderString;      // PBYTE
            public uint Function;             // PDWORD
            public uint Ordinal;              // DWORD
            public uint AddressOfData;        // PIMAGE_IMPORT_BY_NAME
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_THUNK_DATA64
        {
            public ulong ForwarderString;     // PBYTE
            public ulong Function;            // PDWORD
            public ulong Ordinal;             // DWORD
            public ulong AddressOfData;       // PIMAGE_IMPORT_BY_NAME
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_IMPORT_BY_NAME
        {
            public ushort Hint;
            // Variable length array of bytes follows
            // char Name[1];
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_EXPORT_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;
            public uint AddressOfNames;
            public uint AddressOfNameOrdinals;
        }

        // Process Environment Block related structures
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved2;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_USER_PROCESS_PARAMETERS
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] Reserved1;
            public IntPtr Reserved2;
            public IntPtr ImagePathName;
            public IntPtr CommandLine;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            // This is simplified - the actual structure is more complex and differs between x86/x64
            public ulong Rax;
            public ulong Rbx;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip; // Instruction pointer
                              // Many more fields are needed in real implementation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public IntPtr[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr ExceptionRecord;
            public IntPtr ContextRecord;
        }

        // Main entry point delegate for PE files
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int EntryPointDelegate(IntPtr hInstance, uint reason, IntPtr reserved);

        #endregion

        #region Fields

        private IntPtr _baseAddress;
        private bool _disposed;
        private readonly Dictionary<string, IntPtr> _modules;
        private readonly bool _is64Bit;
        private readonly ulong _imageBase;
        private readonly uint _sizeOfImage;
        private readonly IntPtr _entryPoint;
        private readonly ushort _subsystem;
        private string _commandLine;
        private GCHandle _commandLineHandle;
        private IntPtr _commandLinePtr;
        private IntPtr _originalCommandLinePtr;

        // Command line API hooking
        private CommandLineHooking _commandLineHooking;

        #endregion

        #region Properties

        /// <summary>
        /// Gets the base address where the PE file is loaded in memory.
        /// </summary>
        public IntPtr BaseAddress => _baseAddress;

        /// <summary>
        /// Gets the entry point address of the loaded PE file.
        /// </summary>
        public IntPtr EntryPoint => _entryPoint;

        /// <summary>
        /// Gets a value indicating whether the loaded PE file is 64-bit.
        /// </summary>
        public bool Is64Bit => _is64Bit;

        /// <summary>
        /// Gets a value indicating whether the loaded PE file is a GUI application.
        /// </summary>
        public bool IsGuiApplication => _subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;

        #endregion

        #region Constructor and Finalizer

        /// <summary>
        /// Loads a PE file from a byte array into memory.
        /// </summary>
        /// <param name="peBytes">The PE file bytes to load.</param>
        /// <param name="commandLine">Optional command line string that will be visible to the PE file.</param>
        public MemoryPE(byte[] peBytes, string commandLine = null)
        {
            if (peBytes == null || peBytes.Length == 0)
                throw new ArgumentNullException(nameof(peBytes));

            _modules = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
            _commandLine = commandLine;

            // Parse the PE header to determine if it's a 32-bit or 64-bit executable
            GCHandle pinnedArray = GCHandle.Alloc(peBytes, GCHandleType.Pinned);
            try
            {
                IntPtr ptrData = pinnedArray.AddrOfPinnedObject();

                // Read the DOS header
                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(ptrData, typeof(IMAGE_DOS_HEADER));
                if (dosHeader.e_magic != 0x5A4D) // "MZ"
                    throw new BadImageFormatException("Invalid DOS header signature.");

                // Read the PE header
                IntPtr ptrNtHeader = IntPtr.Add(ptrData, dosHeader.e_lfanew);
                uint peSignature = (uint)Marshal.ReadInt32(ptrNtHeader);
                if (peSignature != 0x00004550) // "PE\0\0"
                    throw new BadImageFormatException("Invalid PE header signature.");

                // Read the file header
                IntPtr ptrFileHeader = IntPtr.Add(ptrNtHeader, 4);
                IMAGE_FILE_HEADER fileHeader = (IMAGE_FILE_HEADER)Marshal.PtrToStructure(ptrFileHeader, typeof(IMAGE_FILE_HEADER));

                // Check optional header magic to determine if it's 32-bit or 64-bit
                IntPtr ptrOptionalHeader = IntPtr.Add(ptrFileHeader, Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));
                ushort magic = (ushort)Marshal.ReadInt16(ptrOptionalHeader);

                if (magic == OPTIONAL_HEADER32_MAGIC)
                {
                    _is64Bit = false;
                    IMAGE_OPTIONAL_HEADER32 optionalHeader = (IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER32));
                    _imageBase = optionalHeader.ImageBase;
                    _sizeOfImage = optionalHeader.SizeOfImage;
                    _subsystem = optionalHeader.Subsystem;
                }
                else if (magic == OPTIONAL_HEADER64_MAGIC)
                {
                    _is64Bit = true;
                    IMAGE_OPTIONAL_HEADER64 optionalHeader = (IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER64));
                    _imageBase = optionalHeader.ImageBase;
                    _sizeOfImage = optionalHeader.SizeOfImage;
                    _subsystem = optionalHeader.Subsystem;
                }
                else
                {
                    throw new BadImageFormatException("Invalid optional header magic value.");
                }

                // Allocate memory for the PE file at the preferred base address if possible
                _baseAddress = VirtualAlloc(new IntPtr((long)_imageBase), (UIntPtr)_sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

                // If allocation at preferred base address failed, allocate at any available address
                if (_baseAddress == IntPtr.Zero)
                {
                    _baseAddress = VirtualAlloc(IntPtr.Zero, (UIntPtr)_sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (_baseAddress == IntPtr.Zero)
                        throw new OutOfMemoryException("Failed to allocate memory for PE file.");
                }

                try
                {
                    // Copy the headers
                    uint headerSize = _is64Bit
                        ? ((IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER64))).SizeOfHeaders
                        : ((IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(ptrOptionalHeader, typeof(IMAGE_OPTIONAL_HEADER32))).SizeOfHeaders;

                    if (headerSize > peBytes.Length)
                        throw new BadImageFormatException("Header size is larger than the PE data.");

                    Marshal.Copy(peBytes, 0, _baseAddress, (int)headerSize);

                    // Map sections
                    IntPtr ptrSectionHeader = _is64Bit
                        ? IntPtr.Add(ptrOptionalHeader, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64)))
                        : IntPtr.Add(ptrOptionalHeader, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER32)));

                    for (int i = 0; i < fileHeader.NumberOfSections; i++)
                    {
                        IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ptrSectionHeader, typeof(IMAGE_SECTION_HEADER));

                        if (sectionHeader.SizeOfRawData > 0)
                        {
                            if (sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData > peBytes.Length)
                                throw new BadImageFormatException("Section data extends beyond the PE data.");

                            IntPtr destAddress = IntPtr.Add(_baseAddress, (int)sectionHeader.VirtualAddress);

                            // Copy section data
                            Marshal.Copy(peBytes, (int)sectionHeader.PointerToRawData, destAddress, (int)sectionHeader.SizeOfRawData);
                        }

                        ptrSectionHeader = IntPtr.Add(ptrSectionHeader, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                    }

                    // Process imports
                    ProcessImports();

                    // Process relocations if necessary
                    if (_baseAddress.ToInt64() != (long)_imageBase)
                    {
                        ProcessRelocations();
                    }

                    // Set up custom command line if specified
                    SetupCommandLine();

                    // Set proper memory protection for sections
                    ProtectMemory();

                    // Get the entry point
                    uint entryPointRva = _is64Bit
                        ? ((IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(IntPtr.Add(_baseAddress, dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))), typeof(IMAGE_OPTIONAL_HEADER64))).AddressOfEntryPoint
                        : ((IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(IntPtr.Add(_baseAddress, dosHeader.e_lfanew + 4 + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))), typeof(IMAGE_OPTIONAL_HEADER32))).AddressOfEntryPoint;

                    if (entryPointRva != 0)
                    {
                        _entryPoint = IntPtr.Add(_baseAddress, (int)entryPointRva);
                    }
                    else
                    {
                        throw new InvalidOperationException("PE file has no entry point.");
                    }
                }
                catch
                {
                    VirtualFree(_baseAddress, UIntPtr.Zero, MEM_RELEASE);
                    _baseAddress = IntPtr.Zero;
                    throw;
                }
            }
            finally
            {
                if (pinnedArray.IsAllocated)
                    pinnedArray.Free();
            }
        }

        ~MemoryPE()
        {
            Dispose(false);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Executes the loaded PE file in a separate thread.
        /// </summary>
        /// <param name="waitForExit">Whether to wait for the thread to exit.</param>
        /// <param name="timeout">The maximum time to wait for the thread to exit, in milliseconds, or Timeout.Infinite (-1) to wait indefinitely.</param>
        /// <returns>The exit code returned by the thread, or null if waitForExit is false or the thread did not exit within the timeout.</returns>
        public int? ExecuteInThread(bool waitForExit = true, int timeout = -1)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MemoryPE));

            if (_baseAddress == IntPtr.Zero)
                throw new InvalidOperationException("PE file is not loaded.");

            if (_entryPoint == IntPtr.Zero)
                throw new InvalidOperationException("PE file has no entry point.");

            // Create a thread for execution
            uint threadId;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, _entryPoint, _baseAddress, 0, out threadId);

            if (hThread == IntPtr.Zero)
                throw new InvalidOperationException("Failed to create thread for PE execution.");

            try
            {
                if (waitForExit)
                {
                    uint waitResult = WaitForSingleObject(hThread, timeout <= 0 ? INFINITE : (uint)timeout);

                    if (waitResult == WAIT_OBJECT_0)
                    {
                        uint exitCode;
                        if (GetExitCodeThread(hThread, out exitCode))
                        {
                            return (int)exitCode;
                        }
                    }
                    else if (waitResult == WAIT_TIMEOUT)
                    {
                        // Timeout occurred
                        return null;
                    }
                    else
                    {
                        throw new InvalidOperationException("Failed to wait for PE execution thread.");
                    }
                }

                return null;
            }
            finally
            {
                CloseHandle(hThread);
            }
        }

        #endregion

        #region Private Methods
        private void SetupCommandLine()
        {
            // If no command line was specified, don't modify anything
            if (string.IsNullOrEmpty(_commandLine))
                return;

            // Apply both PEB modification and API hooking for maximum compatibility

            // 1. First, set up API hooking (this works for most applications)
            try
            {
                _commandLineHooking = new CommandLineHooking(_commandLine, _is64Bit);
                _commandLineHooking.ApplyHooks();
                //Console.WriteLine("[Debug] GetCommandLine API hooks applied successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Warning] Failed to apply GetCommandLine API hooks: {ex.Message}");
                // Continue even if hooking fails - we'll still try PEB modification
            }

            // 2. Set up PEB modification (works for applications that read PEB directly)
            try
            {
                // Save the original command line pointer for restoration during cleanup
                _originalCommandLinePtr = GetCommandLine();

                // Ensure the command line ends with a null terminator (for wide strings)
                if (!_commandLine.EndsWith("\0"))
                    _commandLine += "\0";

                // Allocate memory for our custom command line string and pin it
                // We need to pin it so the GC doesn't move it around
                _commandLineHandle = GCHandle.Alloc(_commandLine, GCHandleType.Pinned);
                _commandLinePtr = _commandLineHandle.AddrOfPinnedObject();

                // Get the process environment block (PEB)
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;

                int status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessBasicInformation,
                    ref pbi,
                    Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
                    out returnLength
                );

                if (!NT_SUCCESS(status))
                    throw new InvalidOperationException($"Failed to query process information: 0x{status:X8}");

                // This is a more reliable way to access the ProcessParameters
                // The offsets can vary depending on the Windows version and bitness
                IntPtr pebBaseAddress = pbi.PebBaseAddress;

                // Get the ProcessParameters pointer from the PEB
                // RTL_USER_PROCESS_PARAMETERS is at offset 0x20 in 64-bit and 0x10 in 32-bit
                IntPtr processParamsPtr = Marshal.ReadIntPtr(
                    IntPtr.Add(pebBaseAddress, _is64Bit ? 0x20 : 0x10)
                );

                if (processParamsPtr == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to find ProcessParameters in PEB");

                // Now we need to find the CommandLine UNICODE_STRING structure
                // This is a more robust approach to find it
                IntPtr commandLinePtr;
                ushort commandLineMaxLength, commandLineLength;

                // In the RTL_USER_PROCESS_PARAMETERS struct:
                // - CommandLine is a UNICODE_STRING
                // - The offsets of CommandLine in 64-bit: 0x70 (buffer pointer), 0x68 (length), 0x6A (max length)
                // - The offsets of CommandLine in 32-bit: 0x40 (buffer pointer), 0x38 (length), 0x3A (max length)
                if (_is64Bit)
                {
                    commandLinePtr = IntPtr.Add(processParamsPtr, 0x70);
                    commandLineLength = (ushort)Marshal.ReadInt16(IntPtr.Add(processParamsPtr, 0x68));
                    commandLineMaxLength = (ushort)Marshal.ReadInt16(IntPtr.Add(processParamsPtr, 0x6A));
                }
                else
                {
                    commandLinePtr = IntPtr.Add(processParamsPtr, 0x40);
                    commandLineLength = (ushort)Marshal.ReadInt16(IntPtr.Add(processParamsPtr, 0x38));
                    commandLineMaxLength = (ushort)Marshal.ReadInt16(IntPtr.Add(processParamsPtr, 0x3A));
                }

                // Get the original command line buffer pointer for restoration later
                _originalCommandLinePtr = Marshal.ReadIntPtr(commandLinePtr);

                // Calculate the new length in bytes (UTF-16 = 2 bytes per char)
                // -1 to exclude the null terminator from the length
                ushort newLength = (ushort)((_commandLine.Length - 1) * 2);
                ushort newMaxLength = (ushort)(_commandLine.Length * 2);

                // Make the memory writable
                uint oldProtect;
                IntPtr lengthPtr = IntPtr.Add(processParamsPtr, _is64Bit ? 0x68 : 0x38);
                IntPtr maxLengthPtr = IntPtr.Add(processParamsPtr, _is64Bit ? 0x6A : 0x3A);

                // Protect the memory for writing
                if (!VirtualProtect(lengthPtr, (UIntPtr)4, PAGE_READWRITE, out oldProtect))
                    throw new InvalidOperationException("Failed to change memory protection for command line structure");

                try
                {
                    // Update the UNICODE_STRING structure
                    // 1. Length (in bytes)
                    Marshal.WriteInt16(lengthPtr, (short)newLength);

                    // 2. MaximumLength (in bytes)
                    Marshal.WriteInt16(maxLengthPtr, (short)newMaxLength);

                    // 3. Buffer pointer
                    Marshal.WriteIntPtr(commandLinePtr, _commandLinePtr);
                }
                finally
                {
                    // Restore the original protection
                    VirtualProtect(lengthPtr, (UIntPtr)4, oldProtect, out _);
                }

                // For debugging, let's verify our changes
                string newCommandLine = Marshal.PtrToStringUni(GetCommandLine());
                Console.WriteLine($"[Debug] New command line via PEB: {newCommandLine}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Warning] Failed to modify PEB command line: {ex.Message}");

                // If PEB modification failed but API hooking succeeded, we're still good
                if (_commandLineHooking == null)
                {
                    // Both methods failed, clean up and throw
                    if (_commandLineHandle.IsAllocated)
                        _commandLineHandle.Free();

                    _commandLinePtr = IntPtr.Zero;
                    throw new InvalidOperationException("Failed to set up command line - both PEB modification and API hooking failed", ex);
                }
            }
        }

        private void ProcessImports()
        {
            // Get pointers to PE headers
            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
            IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

            // Get import directory
            IMAGE_DATA_DIRECTORY importDirectory;
            if (_is64Bit)
            {
                IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            }
            else
            {
                IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            }

            if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
                return; // No imports

            IntPtr ptrImportDesc = IntPtr.Add(_baseAddress, (int)importDirectory.VirtualAddress);
            int index = 0;

            while (true)
            {
                IMAGE_IMPORT_DESCRIPTOR importDesc = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                    IntPtr.Add(ptrImportDesc, index * Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR))),
                    typeof(IMAGE_IMPORT_DESCRIPTOR));

                // End of import descriptors
                if (importDesc.Name == 0)
                    break;

                // Get the DLL name
                IntPtr ptrDllName = IntPtr.Add(_baseAddress, (int)importDesc.Name);
                string dllName = Marshal.PtrToStringAnsi(ptrDllName);

                // Load the DLL
                IntPtr hModule;
                if (!_modules.TryGetValue(dllName, out hModule))
                {
                    hModule = LoadLibrary(dllName);
                    if (hModule == IntPtr.Zero)
                        throw new DllNotFoundException($"Failed to load imported DLL: {dllName}");

                    _modules.Add(dllName, hModule);
                }

                // Process the imports
                IntPtr ptrFirstThunk = IntPtr.Add(_baseAddress, (int)importDesc.FirstThunk);
                IntPtr ptrOriginalFirstThunk = importDesc.OriginalFirstThunk != 0
                    ? IntPtr.Add(_baseAddress, (int)importDesc.OriginalFirstThunk)
                    : ptrFirstThunk;

                int thunkIndex = 0;
                while (true)
                {
                    IntPtr thunkAddress = IntPtr.Add(ptrFirstThunk, thunkIndex * (_is64Bit ? 8 : 4));
                    IntPtr originalThunkAddress = IntPtr.Add(ptrOriginalFirstThunk, thunkIndex * (_is64Bit ? 8 : 4));

                    ulong thunkData = _is64Bit
                        ? (ulong)Marshal.ReadInt64(originalThunkAddress)
                        : (uint)Marshal.ReadInt32(originalThunkAddress);

                    // End of imports for this DLL
                    if (thunkData == 0)
                        break;

                    IntPtr functionAddress;

                    if ((thunkData & (_is64Bit ? 0x8000000000000000 : 0x80000000)) != 0)
                    {
                        // Import by ordinal
                        uint ordinal = (uint)(thunkData & 0xFFFF);
                        functionAddress = GetProcAddressByOrdinal(hModule, (IntPtr)ordinal);
                    }
                    else
                    {
                        // Import by name
                        IntPtr ptrImportByName = IntPtr.Add(_baseAddress, (int)thunkData);
                        IMAGE_IMPORT_BY_NAME importByName = (IMAGE_IMPORT_BY_NAME)Marshal.PtrToStructure(ptrImportByName, typeof(IMAGE_IMPORT_BY_NAME));
                        string functionName = Marshal.PtrToStringAnsi(IntPtr.Add(ptrImportByName, 2)); // Skip the Hint field (2 bytes)
                        functionAddress = GetProcAddress(hModule, functionName);
                    }

                    if (functionAddress == IntPtr.Zero)
                        throw new EntryPointNotFoundException($"Failed to find imported function: {dllName} - Function index {thunkIndex}");

                    // Write the function address to the IAT
                    if (_is64Bit)
                        Marshal.WriteInt64(thunkAddress, functionAddress.ToInt64());
                    else
                        Marshal.WriteInt32(thunkAddress, functionAddress.ToInt32());

                    thunkIndex++;
                }

                index++;
            }
        }

        private void ProcessRelocations()
        {
            // Check if relocations are necessary
            long delta = _baseAddress.ToInt64() - (long)_imageBase;
            if (delta == 0)
                return; // No relocations needed

            // Get pointers to PE headers
            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
            IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

            // Get relocation directory
            IMAGE_DATA_DIRECTORY relocationDirectory;
            if (_is64Bit)
            {
                IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                relocationDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }
            else
            {
                IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                relocationDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            }

            if (relocationDirectory.VirtualAddress == 0 || relocationDirectory.Size == 0)
                return; // No relocations

            IntPtr ptrReloc = IntPtr.Add(_baseAddress, (int)relocationDirectory.VirtualAddress);
            uint remainingSize = relocationDirectory.Size;

            while (remainingSize > 0)
            {
                IMAGE_BASE_RELOCATION relocation = (IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(ptrReloc, typeof(IMAGE_BASE_RELOCATION));
                if (relocation.SizeOfBlock == 0)
                    break;

                // Get the number of entries in this block
                int entriesCount = (int)(relocation.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2;

                // Process each entry
                for (int i = 0; i < entriesCount; i++)
                {
                    // Read the relocation entry (2 bytes)
                    ushort entry = (ushort)Marshal.ReadInt16(IntPtr.Add(ptrReloc, Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) + i * 2));

                    // The high 4 bits indicate the type of relocation
                    int type = entry >> 12;

                    // The low 12 bits indicate the offset from the base address of the relocation block
                    int offset = entry & 0xFFF;

                    // Calculate the address to relocate
                    IntPtr ptrAddress = IntPtr.Add(_baseAddress, (int)relocation.VirtualAddress + offset);

                    // Apply the relocation based on type
                    switch (type)
                    {
                        case IMAGE_REL_BASED_ABSOLUTE:
                            // Do nothing, it's a padding entry
                            break;

                        case IMAGE_REL_BASED_HIGHLOW:
                            // 32-bit relocation
                            int value32 = Marshal.ReadInt32(ptrAddress);
                            Marshal.WriteInt32(ptrAddress, value32 + (int)delta);
                            break;

                        case IMAGE_REL_BASED_DIR64:
                            // 64-bit relocation
                            long value64 = Marshal.ReadInt64(ptrAddress);
                            Marshal.WriteInt64(ptrAddress, value64 + delta);
                            break;

                        case IMAGE_REL_BASED_HIGH:
                            // High 16-bits of a 32-bit relocation
                            ushort high = (ushort)Marshal.ReadInt16(ptrAddress);
                            Marshal.WriteInt16(ptrAddress, (short)(high + (short)((delta >> 16) & 0xFFFF)));
                            break;

                        case IMAGE_REL_BASED_LOW:
                            // Low 16-bits of a 32-bit relocation
                            ushort low = (ushort)Marshal.ReadInt16(ptrAddress);
                            Marshal.WriteInt16(ptrAddress, (short)(low + (short)(delta & 0xFFFF)));
                            break;

                        default:
                            throw new NotSupportedException($"Unsupported relocation type: {type}");
                    }
                }

                // Move to the next relocation block
                ptrReloc = IntPtr.Add(ptrReloc, (int)relocation.SizeOfBlock);
                remainingSize -= relocation.SizeOfBlock;
            }
        }

        private void ProtectMemory()
        {
            // Get pointers to PE headers
            IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(_baseAddress, typeof(IMAGE_DOS_HEADER));
            IntPtr ptrNtHeader = IntPtr.Add(_baseAddress, dosHeader.e_lfanew);

            // Get the section headers
            IntPtr ptrSectionHeader;
            int numberOfSections;

            if (_is64Bit)
            {
                IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS64));
                numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                ptrSectionHeader = IntPtr.Add(ptrNtHeader, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
            }
            else
            {
                IMAGE_NT_HEADERS32 ntHeaders = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(ptrNtHeader, typeof(IMAGE_NT_HEADERS32));
                numberOfSections = ntHeaders.FileHeader.NumberOfSections;
                ptrSectionHeader = IntPtr.Add(ptrNtHeader, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS32)));
            }

            // Process each section
            for (int i = 0; i < numberOfSections; i++)
            {
                IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(ptrSectionHeader, typeof(IMAGE_SECTION_HEADER));

                if (sectionHeader.VirtualAddress != 0 && sectionHeader.SizeOfRawData > 0)
                {
                    // Determine the appropriate protection flags
                    uint protect = PAGE_READWRITE; // Default

                    if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    {
                        if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                            protect = PAGE_EXECUTE_READWRITE;
                        else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) != 0)
                            protect = PAGE_EXECUTE_READ;
                        else
                            protect = PAGE_EXECUTE;
                    }
                    else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                    {
                        protect = PAGE_READWRITE;
                    }
                    else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) != 0)
                    {
                        protect = PAGE_READONLY;
                    }

                    // Calculate the section's memory size (aligned to page size)
                    IntPtr sectionAddress = IntPtr.Add(_baseAddress, (int)sectionHeader.VirtualAddress);
                    uint oldProtect;

                    // Apply the protection
                    if (!VirtualProtect(sectionAddress, (UIntPtr)sectionHeader.SizeOfRawData, protect, out oldProtect))
                        throw new InvalidOperationException($"Failed to set memory protection for section {i}");
                }

                ptrSectionHeader = IntPtr.Add(ptrSectionHeader, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            }
        }

        /// <summary>
        /// Restores the original command line in the PEB if it was modified.
        /// </summary>
        private void RestoreCommandLine()
        {
            // First, remove any API hooks
            if (_commandLineHooking != null)
            {
                try
                {
                    _commandLineHooking.RemoveHooks();
                    _commandLineHooking.Dispose();
                    _commandLineHooking = null;
                    //Console.WriteLine("[Debug] GetCommandLine API hooks removed successfully");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Warning] Error removing GetCommandLine API hooks: {ex.Message}");
                }
            }

            // Then restore the PEB if we modified it
            if (_commandLinePtr != IntPtr.Zero && _originalCommandLinePtr != IntPtr.Zero)
            {
                try
                {
                    // Get the process environment block (PEB)
                    PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                    int returnLength;

                    int status = NtQueryInformationProcess(
                        GetCurrentProcess(),
                        ProcessBasicInformation,
                        ref pbi,
                        Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
                        out returnLength
                    );

                    if (NT_SUCCESS(status))
                    {
                        // Get the ProcessParameters pointer
                        IntPtr processParamsPtr = Marshal.ReadIntPtr(
                            IntPtr.Add(pbi.PebBaseAddress, _is64Bit ? 0x20 : 0x10)
                        );

                        if (processParamsPtr != IntPtr.Zero)
                        {
                            // Get the original command line buffer pointer
                            IntPtr commandLinePtr = IntPtr.Add(processParamsPtr, _is64Bit ? 0x70 : 0x40);

                            // Make the memory writable
                            uint oldProtect;
                            if (VirtualProtect(commandLinePtr, (UIntPtr)IntPtr.Size, PAGE_READWRITE, out oldProtect))
                            {
                                // Restore the original command line buffer pointer
                                Marshal.WriteIntPtr(commandLinePtr, _originalCommandLinePtr);

                                // Restore protection
                                VirtualProtect(commandLinePtr, (UIntPtr)IntPtr.Size, oldProtect, out _);

                                //Console.WriteLine("[Debug] Original command line restored in PEB");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Warning] Error restoring command line in PEB: {ex.Message}");
                }

                // Free the pinned command line string
                if (_commandLineHandle.IsAllocated)
                    _commandLineHandle.Free();

                _commandLinePtr = IntPtr.Zero;
            }
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes the memory PE and frees all resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            RestoreCommandLine();
            return;
        }

        #endregion
    }
}
