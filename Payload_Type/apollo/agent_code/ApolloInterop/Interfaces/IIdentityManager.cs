using ApolloInterop.Structs.ApolloStructs;
using ApolloInterop.Structs.MythicStructs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace ApolloInterop.Interfaces
{
    public interface IIdentityManager
    {
        WindowsIdentity GetCurrent();
        WindowsIdentity GetOriginal();

        void Revert();

        bool SetIdentity(WindowsIdentity identity);

        bool SetIdentity(ApolloLogonInformation token);

        IntegrityLevel GetIntegrityLevel();

    }
}
