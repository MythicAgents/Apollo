using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Security.Principal;

namespace ApolloInterop.Interfaces
{
    public interface IIdentityManager
    {
        WindowsIdentity GetCurrentPrimaryIdentity();
        WindowsIdentity GetCurrentImpersonationIdentity();
        WindowsIdentity GetOriginal();

        bool GetCurrentLogonInformation(out ApolloLogonInformation logonInfo);

        void Revert();

        bool SetIdentity(ApolloLogonInformation token);
        bool SetIdentity(IntPtr hToken);

        IntegrityLevel GetIntegrityLevel();

        bool IsOriginalIdentity();

        bool GetSystem();
        bool RunAsSystem(Action<WindowsIdentity> action);

    }
}
