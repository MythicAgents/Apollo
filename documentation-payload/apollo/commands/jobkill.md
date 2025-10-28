+++
title = "jobkill"
chapter = false
weight = 103
hidden = false
+++

## Summary
The `jobkill` function terminates running jobs (tasks) within the Apollo agent by their job identifiers. The command supports killing multiple jobs simultaneously and includes special handling for specific command types like `rpfwd`. It provides feedback on the success or failure of each termination attempt.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **jid** (String) - Job identifier(s) to terminate (space-separated for multiple jobs)
  - **Required:** True

## Usage
```
jobkill [task_id_guid]
```

![jobs](../images/jobs.png)

### Example 1: Kill Single Job
**Command:**
```
jobkill abc123-def4-5678-9abc-def123456789
```
**Output:**
```text
Killed abc123-def4-5678-9abc-def123456789
```

### Example 2: Kill Multiple Jobs
**Command:**
```
jobkill job1 job2 job3
```
**Output:**
```text
Killed job1
Killed job2
Failed to kill job3
```

### Example 3: Kill Nonexistent Job
**Command:**
```
jobkill invalid-job-id
```
**Output:**
```text
Failed to kill invalid-job-id
```

## Detailed Summary

The `jobkill` function implements a job termination system with support for multiple job types and special command handling:

### 1. Parameter Processing and Job ID Parsing

The command processes job identifiers from the command line parameters:

```csharp
public override void Start()
{
    string[] jids = _data.Parameters.Split(' ');
    foreach (string j in jids)
    {
        // Job termination logic
    }
}
```

**Parameter Processing**:
* **Space Separation**: Splits parameters by spaces to handle multiple job IDs
* **Individual Processing**: Processes each job ID separately
* **Result Tracking**: Tracks success/failure for each termination attempt

### 2. Core Job Termination Implementation

The C# implementation handles the actual job cancellation:

```csharp
foreach (string j in jids)
{
    if (_agent.GetTaskManager().CancelTask(j))
    {
        _agent.GetTaskManager().AddTaskResponseToQueue(
            CreateTaskResponse($"Killed {j}", false, ""));
    }
    else
    {
        _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
            $"Failed to kill {j}", false, ""));
        bRet = false;
    }
}
```

**Termination Process**:
* **Task Manager Integration**: Uses `GetTaskManager().CancelTask()` to terminate jobs
* **Success Feedback**: Reports successful terminations with job ID
* **Failure Tracking**: Reports failed terminations and sets error flag
* **Individual Results**: Provides feedback for each job termination attempt

### 3. Special Command Handling for RPFWD

The Python handler includes special processing for `rpfwd` commands:

```python
if killedTaskResp.Tasks[0].CommandName == "rpfwd":
    try:
        params = json.loads(killedTaskResp.Tasks[0].Params)
        rpfwdStopResp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
            TaskID=taskData.Task.ID,
            PortType="rpfwd",
            Port=params["port"],
            Username=params["username"] if "username" in params else "",
            Password=params["password"] if "password" in params else "",
        ))
```

**RPFWD Special Handling**:
* **Task Search**: Searches for the target task using `SendMythicRPCTaskSearch`
* **Command Detection**: Checks if the target task is an `rpfwd` command
* **Parameter Extraction**: Parses JSON parameters from the original task
* **Proxy Stop**: Calls `SendMythicRPCProxyStopCommand` to stop Mythic's proxy components
* **Status Reporting**: Reports success or failure of proxy component shutdown

### 4. Task Manager Integration and Cancellation

The command integrates with Apollo's task management system:

**Task Cancellation Process**:
* **Task Lookup**: TaskManager locates the job by identifier
* **Cancellation Request**: Calls cancellation method on the target task
* **Resource Cleanup**: TaskManager handles cleanup of associated resources
* **Status Update**: Returns boolean indicating cancellation success

### 5. Response Generation and Status Reporting

The command provides detailed feedback for termination attempts:

```csharp
_agent.GetTaskManager().AddTaskResponseToQueue(
    CreateTaskResponse(
        "",
        true,
        bRet ? "completed" : "error"));
```

**Response Characteristics**:
* **Individual Feedback**: Reports results for each job ID separately
* **Final Status**: Provides overall completion status
* **Error Indication**: Sets error status if any termination fails
* **Empty Final Message**: Final response contains empty message body

### 6. Command Configuration and Attributes

```python
class JobkillCommand(CommandBase):
    cmd = "jobkill"
    needs_admin = False
    help_cmd = "jobkill [jid]"
    description = "Kill a job specified by the job identifier (jid)."
    version = 2
    is_exit = False
    supported_ui_features = ["jobkill", "task:job_kill"]
    author = "@djhohnstein"
    argument_class = JobkillArguments
    attackmapping = []
```

**Configuration Details**:
* **No Admin Required**: Can be executed with standard privileges
* **UI Features**: Supports UI-based job killing features
* **Not Exit Command**: Does not cause agent to exit
* **No Attack Mapping**: Purely administrative function

### 7. Argument Validation and Error Handling

```python
async def parse_arguments(self):
    if len(self.command_line) == 0:
        raise Exception("Require Job ID to terminate as a command line argument.")
```

**Validation Process**:
* **Required Parameter**: Ensures at least one job ID is provided
* **Exception Handling**: Throws exception for missing parameters
* **Command Line Processing**: Processes raw command line input

### 8. Mythic RPC Integration and Communication

The Python handler integrates with Mythic's RPC system:

**RPC Operations**:
* **Task Search**: `SendMythicRPCTaskSearch` to locate target tasks
* **Proxy Control**: `SendMythicRPCProxyStopCommand` for rpfwd cleanup
* **Response Creation**: `SendMythicRPCResponseCreate` for status updates

### 9. Error Handling and Exception Management

The implementation includes error handling for various scenarios:

**Error Scenarios**:
* **Invalid Job IDs**: Reports failure when job ID doesn't exist
* **Cancellation Failures**: Handles cases where task cancellation fails
* **JSON Parsing Errors**: Catches and logs JSON parsing failures for rpfwd params
* **RPC Communication Errors**: Handles failures in Mythic RPC operations

### 10. Multi-Job Support and Batch Processing

The command supports terminating multiple jobs in a single command:

**Batch Processing Features**:
* **Space-Separated IDs**: Accepts multiple job IDs separated by spaces
* **Individual Processing**: Processes each job ID independently
* **Partial Success Handling**: Continues processing even if some jobs fail
* **Aggregate Status**: Provides overall success/failure status

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `IAgent.GetTaskManager().CancelTask()` | Cancels running task by ID | Apollo Agent | Internal Apollo API |
| `SendMythicRPCTaskSearch()` | Searches for task information | Mythic RPC | Internal Mythic API |
| `SendMythicRPCProxyStopCommand()` | Stops proxy components | Mythic RPC | Internal Mythic API |
| `SendMythicRPCResponseCreate()` | Creates response messages | Mythic RPC | Internal Mythic API |
| `String.Split()` | Parses space-separated job IDs | mscorlib.dll | [String.Split](https://docs.microsoft.com/en-us/dotnet/api/system.string.split) |

## Job Identification and Management

### Job ID Format
Job IDs in Apollo are typically UUIDs or task identifiers that correspond to running tasks.

### Task Lifecycle
1. **Task Creation**: Tasks are created and assigned unique identifiers
2. **Execution**: Tasks run asynchronously within the agent
3. **Monitoring**: Tasks can be monitored through the `jobs` command
4. **Termination**: Tasks can be terminated using `jobkill`

### Special Command Types
Some commands require special handling during termination:
- **rpfwd**: Requires stopping Mythic proxy components
- **Long-running tasks**: May need additional cleanup
- **Network operations**: May require connection cleanup

## Response Format

### Successful Termination
```text
Killed [job-id]
```

### Failed Termination
```text
Failed to kill [job-id]
```

### RPFWD Special Messages
```text
Stopped Mythic's rpfwd components
```
or
```text
Failed to stop Mythic's rpfwd components: [error]
```

## Limitations

1. Cannot kill tasks that have already completed
2. Some tasks may not respond immediately to cancellation
3. Requires valid job IDs (no pattern matching or wildcards)
4. Cannot undo job termination once executed
5. Limited error details for termination failures
6. Does not show running jobs (use `jobs` command first)

## References

- [Apollo Agent Source Code](https://github.com/MythicAgents/Apollo)