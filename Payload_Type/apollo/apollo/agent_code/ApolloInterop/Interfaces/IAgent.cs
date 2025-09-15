﻿using System.Threading;
using ApolloInterop.Features.KerberosTickets;

namespace ApolloInterop.Interfaces
{
    public interface IAgent
    {
        // Start the agent.
        void Start();

        // Kill the agent.
        void Exit();

        // Set agent sleep
        void SetSleep(int seconds, double jitter=0);

        // Do sleep until a wait handle triggers
        void Sleep(WaitHandle[] handles = null);

        // Return if we're connected to Mythic or another peer
        bool IsAlive();

        // Return the current UUID of the agent.
        string GetUUID();

        // Set a new UUID of the agent.
        void SetUUID(string newUUID);

        // Lock standard handles of the agent.
        void AcquireOutputLock();

        // Release the lock on the standard handles of the agent.
        void ReleaseOutputLock();

        // Return the ITaskManager interface. Manages all aspects of tasking.
        ITaskManager GetTaskManager();

        // Return the IPeerManager interface. Manages connected P2P nodes.
        IPeerManager GetPeerManager();

        // Return the ISocksManager interface. Responsible for forwarding SOCKS packets.
        ISocksManager GetSocksManager();

        // Return the IRpfwdManager interface. Responsible for forwarding Rpfwd packets.
        IRpfwdManager GetRpfwdManager();

        // Return the IC2ProfileManager interface. Used to add, update, delete, or change C2 rotations.
        IC2ProfileManager GetC2ProfileManager();

        // Return the IFileManager interface. Used to get and push files to Mythic.
        IFileManager GetFileManager();

        // Return the IIdentityManager interface. Used for updating currently executing identity context.
        IIdentityManager GetIdentityManager();

        // Return IProcessManager interface. Used for creating new processes.
        IProcessManager GetProcessManager();

        // Return IInjectionManager interface. Used for managing how injection is performed and injecting into processes
        IInjectionManager GetInjectionManager();
        
        // Return ITicketManager interface. Used for managing Kerberos tickets.
        ITicketManager GetTicketManager();

        // Return IApi interface. Used for resolving native Win32 API calls, RSA cryptography, and otherwise.
        IApi GetApi();
    }
}
