+++
title = "Apollo Interfaces"
chapter = true
weight = 25
pre = "<b>4. </b>"
+++

## Overview

Apollo uses the [dependency injection design pattern ](https://www.tutorialsteacher.com/ioc/dependency-injection) in all profiles, tasks, and feature sets. The primary dependency is communicated using the interface `IAgent`. This interface allows other parts of the agent to:
- Send and retrieve files
- Store and encrypt files
- Request Windows native API functions
- Modify identity contexts
- Create, start, and inject into processes
- Add or modify C2 profiles
- Lock standard handles of the process
- Terminate the agent

## IAgent Interface

```
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
```