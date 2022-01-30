+++
title = "Creating a New Task"
chapter = false
weight = 25
+++

## Creating a New Task

Tasks fall under two categories: script only tasks, and atomic tasks. 

## Script Only Tasks

Script only tasks orchestrate one or more tasks that are already built-in to Apollo. For example, think about a `psexec` command. This command would first want to perform an `upload` to a target, then issue an `sc` command to create a new service, then another `sc` command to start the service. All you should need to do is add a new python file under `Payload_Type/apollo/mythic/agent_functions/` named `mycommand.py`. This file should be of the format:

```
// import statements here

class MyCommandArguments(TaskArguments):

    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            ...
        ]

    async def parse_arguments(self):
        ...


class MyCommandCommand(CommandBase):
    cmd = "my_command"
    attributes=CommandAttributes(
        dependencies=["execute_pe"]
    )
    ... other attributes ...

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
```

Of note, if your command requires one or more dependencies to be loaded into the agent, you should specify them in the list of `dependencies` that are defined under `MyCommandCommand["attributes"]`. To perform task delegation, see Mythic documentation, or other examples of script only commands in Apollo, such as `pth`, `dcsync`, `mimikatz`, and otherwise.

## Atomic Tasks

Atomic tasks are defined as new tasks to be added in the core of the agent. These types of tasks have no dependencies and are discrete taskings in and of themselves. New atomic tasks should be created under the `Tasks` project of the Apollo solution, as `my_command.cs`. This new file should contain a class, `public class my_command`, that inherits from the `Tasking` base class.


### Tasking Base Class

The `Tasking` base class that all tasks inherit from have the following special variables:
1. `IAgent _agent` - Dependency resolver.
2. `Task _data` - A .NET representation of the task data sent from Mythic
3. `JsonSerializer _jsonSerializer` - An object that can serialize .NET objects to JSON strings and deserialize JSON strings to .NET objects.

Lastly, all tasks that inherit this class will use the `CreateTaskResponse` function, which is defined as the following:

```
public virtual TaskResponse CreateTaskResponse(
    object userOutput,                           // What the user will see
    bool completed,                              // If the task is finished executing
    string status = "completed",                 // Status of task execution.
    IEnumerable<IMythicMessage> messages = null  // List of additional IMythicMessages
)
```

These `TaskResponse` objects are what are added to the queue via the `ITaskManager.AddTaskResponseToQueue` function, which ultimately sends data from the executing task back to Mythic (discussed later). What you should know, as a user, is that:
1. `userOutput` is what is sent in the `user_output` field of a task to Mythic.
2. `messages` is a list of additional typed messages Mythic can interpret and feed into various parts of it's UI.

The `messages` variable is a list of `IMythicMessage` types, which can be one of the following:
- `CommandInformation` - Information about loaded commands
- `EdgeNode` - Updating the P2P nodes this agent knows about or is connected to
- `FileBrowser` - Updating data in Mythic's file browser
- `Credential` - Adding new credentials to the Mythic store
- `RemovedFileInformation` - Tracking file deletions in Mythic
- `Artifact` - Artifacts from task execution. Includes process creation events, logons, file deletions, etc.
- `UploadMessage` - A special message type telling Mythic you're retrieving a file from it.
- `DownloadMessage` - A special message type telling Mythic you're pushing a data to the Mythic server
- `ProcessInformation` - Updates information in Mythic's process browser
- `KeylogInformation` - Information about a user's keypresses.

### Example `my_command.cs` File

```
#define COMMAND_NAME_UPPER

#if DEBUG
#define MY_COMMAND
#endif

#if MY_COMMAND

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using System.Runtime.Serialization;
using ApolloInterop.Serializers;
using System.Threading;
using System.IO;

namespace Tasks
{
    public class my_command : Tasking
    {
        [DataContract]
        public struct MyCommandParameters
        {
            [DataMember(Name = "param_name")] public string ParamName;
        }
        public my_command(IAgent agent, Task task) : base(agent, task)
        {
            /*
             * Initiliaze any variables that'll be required for task execution, such as
             * getting function pointers to Win32 APIs through agent.GetApi().GetLibraryFunction,
             * asynchronous tasks that push data to Mythic if output streaming is required,
             * etc.
             */
        }

        public override void Start()
        {
            MyCommandParameters parameters = _jsonSerializer.Deserialize<MyCommandParameters>(_data.Parameters);
            TaskResponse resp;
            /*
             * Do the main bulk of work of the function here. When you want to submit data to Mythic,
             * create a new TaskResponse, and add it to the response queue.
             */
            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                $"This is the data I want to display to the user",
                true // Whether or not the task has completed));
        }
    }
}
#endif
```

### IAgent Interface

The IAgent interface is a dependency leveraged heavily throughout the agent. More reading on the interface can be done in the "Available Interfaces" documentation (may or may not be complete at the time of writing). You can use this interface to perform the following:

1. Get the agent's `IFileManager` interface, responsible for storing, fetching, and sending files to Mythic.
2. Get the agent's `IProcessManager` interface, responsible for creating new child processes.
3. Get the agent's `IInjectionManager` interface, responsible for injecting shellcode into processes.
4. Get the agent's `ITaskManager` interface, responsible for loading commands, dispatching new tasks, and adding output from tasks to the sending queue.

This is by no means an exhaustive list of interfaces `IAgent` presents nor is it meant as a full list of the capabilities of each of the aforementioned interfaces. The following are just what's most frequently used during Task development.

### IFileManager Interface

The IFileManager interface is used by tasking to perform the following.

1. Get a file from Mythic by its file ID. The result of this operation will yield the file from Mythic in the `fileBytes` variable shown below:
```
_agent.GetFileManager().GetFile(
    _cancellation.Token,
    _data.ID
    fileId,
    out byte[] fileBytes
)
```
2. Send a file to Mythic via the `PutFile` call:
```
_agent.GetFileManager().PutFile(
    _cancellationToken.Token,
    _data.ID,
    fileBytes,               // The file you're sending to Mythic
    filePath,                // Where the file originated
    out string mythicFileId, // The file ID Mythic assigned to your file
    false,                   // Whether or not this file is a screenshot
    parameters.Hostname      // The host where this file was found
)
```
3. Retrieve a file from the agent's cache. Some tasks use the file cache to fetch files required for execution, as it reduces latency from task issuance to task execution. Some examples are:
- `execute_assembly` - Fetches assemblies previously registered via `register_file` from the file cache to execute in a sacrifical process
- `powershell` - Fetches the currently loaded PowerShell script from the file cache.
```
_agent.GetFileManager().GetFileFromStore(
    fileName,
    out byte[] fileBytes)
```

### IProcessManager

The IProcessManager interface is responsible for:
- Spawning new child processes
- Setting the parent process ID of child processes (`ppid`)
- Blocking non-Microsoft DLL's from being loaded into the process (`block_dlls`)
- Setting the default process to spawn used in fork and run tasks (`spawnto_*`)
- Retrieving default application startup arguments.

#### Spawning a Child Process

Spawning a new child process can be done via:
```
_agent.GetProcessManager().NewProcess(
    string lpApplication,
    string lpArguments,
    bool startSuspended = false,
)
```
This returns a new `Process` object (defined in `ApolloInterop`) which is distinct from the traditional `System.Diagnostics.Process` object. You can subscribe to this process's stdout and stderr by adding an event handler to the `Process` object's `OutputDataReceived` and `ErrorDataReceived`. Once you have your event handlers configured, you can issue `Process.Start()` to start process execution, and similarily, `WaitForExit` if you wish to wait for the process to exit.

Should you need to inject shellcode into a process, the `Process.Inject` method will inject arbitrary shellcode into the process using the currently defined injection method in the `IInjectionManager` implementation in use.

### IInjectionManager

This interface is responsible for retrieving the loaded injection techniques, changing which technique is in use for post-ex jobs, as well as giving callers the ability to inject into arbitrary processes.

Namely, `IInjectionManager.CreateInstance` will allow the caller to create an instance of injection to a target process, then a separate call to `InjectionTechnique.Inject` will inject the shellcode. 

### ITaskManager

The `ITaskManager` interface is what Tasks will most heavily interface with. Notably, this interface will push output from tasks up to Mythic for the user to see, load new taskings, cancel running tasks, and otherwise.

As a Task developer, you'll mostly look to use `ITaskManager.AddTaskResponseToQueue`, which adds a new `TaskResponse` message to be sent to Mythic. These `TaskResponse` objects should be created via the `Tasking` base class's `Tasking.CreateTaskResponse`, which populates the requisite fields.