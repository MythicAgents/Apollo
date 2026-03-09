using System;
using System.Security.Principal;

namespace ApolloInterop.Classes.Impersonation
{
    public static class ImpersonationScope
    {
        public static void Run(WindowsIdentity identity, Action action)
        {
            if (identity == null)
                throw new ArgumentNullException(nameof(identity));
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            using (identity.Impersonate())
            {
                action();
            }
        }

        public static T Run<T>(WindowsIdentity identity, Func<T> action)
        {
            if (identity == null)
                throw new ArgumentNullException(nameof(identity));
            if (action == null)
                throw new ArgumentNullException(nameof(action));

            using (identity.Impersonate())
            {
                return action();
            }
        }
    }
}
