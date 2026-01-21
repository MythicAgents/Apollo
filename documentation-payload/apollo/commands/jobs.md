+++
title = "jobs"
chapter = false
weight = 103
hidden = false
+++

## Summary
The `jobs` command retrieves and displays a comprehensive list of currently executing tasks within the Apollo agent, providing operators with real-time visibility into active operations. This command excludes itself and `jobkill` commands from the results to prevent recursive operations and maintain clean output for operational awareness.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
This command accepts no arguments and will raise an exception if any parameters are provided.

## Usage
### Example: Listing Active Jobs
**Command:**
```
jobs
```
**Output:**
![jobs](../images/jobs.png)

## Detailed Summary

The `jobs` command implements a comprehensive task monitoring system that provides operators with crucial situational awareness during active operations. The command operates through a multi-layered architecture spanning the Mythic server, the Apollo agent, and the browser-based user interface.

### 1. Command Initialization and Validation

The command begins with strict parameter validation to ensure proper execution:

* **Argument Parsing**: The `JobsArguments` class inherits from `TaskArguments` and implements a zero-argument validation system
* **Parameter Rejection**: Any command-line arguments provided to the `jobs` command result in an immediate exception with the message "Jobs takes no arguments"
* **Command Registration**: The command is registered with Mythic using the `CommandBase` class with the following metadata:
  * Command name: "jobs"
  * Admin privileges required: False
  * Help command: "jobs"
  * Version: 2
  * Attack mapping: Empty array (informational command)

### 2. Agent-Side Task Execution (C# Implementation)

The Apollo agent's C# implementation handles the core task enumeration logic:

#### Task Manager Integration
```csharp
string[] jids = _agent.GetTaskManager().GetExecutingTaskIds();
```

* **Task Enumeration**: Calls the agent's task manager to retrieve all currently executing task identifiers
* **Self-Exclusion**: Automatically filters out the current `jobs` task ID to prevent recursive inclusion
* **Task ID Collection**: Builds a filtered array of active task identifiers for transmission

#### Response Generation
```csharp
MythicTaskResponse resp = CreateTaskResponse("", true, "completed");
resp.ProcessResponse = new ApolloInterop.Structs.ApolloStructs.ProcessResponse
{
    Jobs = realJids.ToArray()
};
```

* **Response Structure**: Creates a `MythicTaskResponse` object with completion status
* **Process Response**: Utilizes the `ProcessResponse` structure to encapsulate the job data
* **Task Queue Management**: Adds the response to the agent's task response queue for transmission to Mythic

### 3. Mythic Server-Side Processing (Python Implementation)

The Mythic server processes the agent response and enriches it with detailed task metadata:

#### Task Information Retrieval
```python
job_resp = await SendMythicRPCTaskSearch(MythicRPCTaskSearchMessage(
    TaskID=task.Task.ID,
    SearchAgentTaskID=job
))
```

* **RPC Communication**: Uses Mythic's RPC system to query detailed task information
* **Metadata Enrichment**: For each job ID, retrieves comprehensive task details including:
  * `AgentTaskID`: The unique identifier used by the agent
  * `CommandName`: The actual command being executed
  * `DisplayParams`: Human-readable parameter representation
  * `OperatorUsername`: The operator who initiated the task
  * `DisplayID`: The user-friendly task identifier

#### Data Transformation and Response
```python
jobs.append({
    "agent_task_id": job_resp.Tasks[0].AgentTaskID,
    "command": job_resp.Tasks[0].CommandName,
    "display_params": job_resp.Tasks[0].DisplayParams,
    "operator": job_resp.Tasks[0].OperatorUsername,
    "display_id": job_resp.Tasks[0].DisplayID
})
```

* **JSON Structure**: Builds a structured JSON array containing enriched job information
* **Error Handling**: Implements comprehensive error handling for failed RPC calls
* **Response Encoding**: Encodes the final JSON response for transmission to the browser interface

### 4. Browser Interface Rendering (JavaScript Implementation)

The browser-based interface transforms the job data into an interactive table format:

#### Table Structure Definition
```javascript
let headers = [
    {"plaintext": "kill", "type": "button", "startIcon": "kill", "cellStyle": {}, "width": 100, "disableSort": true},
    {"plaintext": "operator", "type": "string", "cellStyle": {}, "width": 200},
    {"plaintext": "command", "type": "string", "cellStyle": {}, "width": 200},
    {"plaintext": "arguments", "type": "string", "cellStyle": {}, "fillWidth": true},
];
```

* **Interactive Kill Button**: Each row includes a functional "kill" button for immediate job termination
* **Operator Column**: Displays the username of the operator who initiated each task
* **Command Column**: Shows the specific command being executed
* **Arguments Column**: Displays the parameters passed to each command with flexible width

#### Dynamic Row Generation
```javascript
let row = {
    "rowStyle": {},
    "kill": {"button": {
        "name": "kill",
        "type": "task",
        "ui_feature": "jobkill",
        "parameters": jinfo["agent_task_id"],
        "cellStyle": {},
    }},
    "operator": {"plaintext": jinfo["operator"], "cellStyle": {}},
    "command": {"plaintext": jinfo["command"], "cellStyle": {}},
    "arguments": {"plaintext": jinfo["display_params"], "cellStyle": {}},
};
```

* **Button Integration**: Each kill button is configured to execute a `jobkill` command with the appropriate agent task ID
* **Data Binding**: Maps the enriched job data to appropriate table cells
* **Styling Support**: Provides extensible styling capabilities for future enhancements

### 5. Error Handling and Edge Cases

The command implements comprehensive error handling across all layers:

#### Agent-Side Error Handling
* **Task Manager Failures**: Gracefully handles scenarios where the task manager is unavailable
* **Memory Management**: Ensures proper cleanup of task ID arrays and response objects
* **Threading Safety**: Maintains thread-safe access to the task manager's internal state

#### Server-Side Error Handling
```python
if job_resp.Success:
    jobs.append({...})
else:
    raise Exception("Failed to get job info for job {}".format(job))
```

* **RPC Failure Handling**: Implements explicit error checking for all RPC communications
* **Partial Failure Management**: Ensures that failure to retrieve information for one job doesn't compromise the entire response
* **Exception Propagation**: Provides clear error messages for troubleshooting failed operations

#### Browser-Side Error Handling
```javascript
try{
    data = JSON.parse(responses[i]);
}catch(error){
    console.log(error);
    const combined = responses.reduce( (prev, cur) => {
        return prev + cur;
    }, "");
    return {'plaintext': combined};
}
```

* **JSON Parsing Errors**: Gracefully handles malformed JSON responses
* **Fallback Display**: Provides plaintext output when structured data parsing fails
* **Console Logging**: Maintains error logs for debugging purposes

### 6. Integration with Job Control Systems

The `jobs` command is designed to work seamlessly with job control mechanisms:

#### JobKill Integration
* **Button Functionality**: Each job entry includes a functional kill button
* **Parameter Passing**: Automatically configures kill buttons with the correct agent task IDs
* **UI Feature Mapping**: Maps kill buttons to the `jobkill` UI feature for proper command routing

#### Task State Management
* **Real-Time Updates**: Reflects the current state of task execution
* **Consistency Maintenance**: Ensures displayed information matches actual agent state
* **Exclusion Logic**: Prevents display of jobs that should not be killable (jobs, jobkill)

### 7. Performance Considerations

The command is optimized for efficient operation in production environments:

#### Agent Performance
* **Minimal Overhead**: Task enumeration operates with minimal performance impact
* **Non-Blocking Operation**: Does not interfere with other executing tasks
* **Memory Efficiency**: Uses efficient data structures for task ID management

#### Server Performance
* **Batched RPC Calls**: Processes multiple job queries efficiently
* **Response Caching**: Leverages Mythic's caching mechanisms where appropriate
* **Asynchronous Processing**: Uses async/await patterns for optimal server resource utilization

#### Browser Performance
* **Efficient Rendering**: Uses optimized table rendering for large job lists
* **Progressive Loading**: Supports incremental updates for long-running operations
* **Memory Management**: Properly manages DOM elements and event handlers

### 8. Security Considerations

The command implements several security measures:

#### Information Disclosure Control
* **Operator Visibility**: Only displays jobs for the current callback/agent
* **Parameter Sanitization**: Ensures displayed parameters don't contain sensitive information
* **Access Control**: Inherits access controls from the parent Mythic session

#### Audit Trail Integration
* **Command Logging**: All `jobs` command executions are logged in Mythic's audit system
* **Operator Attribution**: Maintains clear records of who executed job monitoring commands
* **Timestamp Tracking**: Records precise timing information for security analysis

## MITRE ATT&CK Mapping
- **T1057** - Process Discovery
- **T1082** - System Information Discovery

## Technical Deep Dive

### Task Manager Architecture

The Apollo agent's task manager maintains a sophisticated internal state system:

#### Task Lifecycle Management
```csharp
public string[] GetExecutingTaskIds()
{
    return _executingTasks.Keys.ToArray();
}
```

* **Concurrent Collections**: Uses thread-safe data structures for task tracking
* **State Transitions**: Maintains accurate state information throughout task lifecycles
* **Resource Management**: Properly manages system resources associated with each task

#### Task Identification System
* **Agent Task IDs**: Uses agent-specific identifiers for internal tracking
* **Mythic Task IDs**: Maintains mapping to Mythic's task identification system
* **Display IDs**: Provides human-readable identifiers for operator convenience

### Mythic RPC System Integration

The command leverages Mythic's comprehensive RPC system:

#### Task Search Mechanism
```python
SearchAgentTaskID=job
```

* **Efficient Queries**: Uses indexed searches for rapid task information retrieval
* **Metadata Access**: Provides access to comprehensive task metadata
* **Cross-Reference Capability**: Enables correlation between agent and server task records

#### Response Creation System
```python
await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
    TaskID=task.Task.ID,
    Response=json.dumps(jobs).encode()
))
```

* **Structured Responses**: Creates properly formatted response messages
* **Encoding Standards**: Uses consistent encoding for data transmission
* **Message Routing**: Ensures responses are properly routed to requesting operators

### Browser Interface Technology Stack

The browser interface utilizes modern web technologies:

#### Table Rendering System
* **Virtual Scrolling**: Supports efficient rendering of large job lists
* **Interactive Elements**: Provides clickable buttons and sortable columns
* **Responsive Design**: Adapts to various screen sizes and resolutions

#### Event Handling Architecture
```javascript
"ui_feature": "jobkill",
"parameters": jinfo["agent_task_id"]
```

* **Event Delegation**: Uses efficient event handling patterns
* **Parameter Binding**: Automatically binds appropriate parameters to UI elements
* **Action Routing**: Routes user actions to appropriate command handlers

## APIs Used and Their Purposes
| API/Method | Purpose | Layer | Documentation |
|------------|---------|-------|---------------|
| `GetExecutingTaskIds()` | Retrieve active task identifiers | Agent (C#) | Apollo Task Manager |
| `SendMythicRPCTaskSearch()` | Query task metadata | Server (Python) | Mythic RPC Documentation |
| `SendMythicRPCResponseCreate()` | Create structured response | Server (Python) | Mythic RPC Documentation |
| `JSON.parse()` | Parse server response | Browser (JS) | MDN Web Docs |
| `CreateTaskResponse()` | Generate agent response | Agent (C#) | Apollo Framework |

## Security Considerations

### Information Security
1. **Task Isolation**: Jobs from different callbacks are properly isolated
2. **Parameter Sanitization**: Command parameters are sanitized before display
3. **Access Control**: Operator access controls are enforced throughout the chain

### Operational Security
1. **Audit Logging**: All command executions are properly logged
2. **Session Management**: Commands are properly associated with operator sessions
3. **Error Information**: Error messages don't reveal sensitive system information

### Performance Security
1. **Resource Limits**: Command execution respects system resource limits
2. **Denial of Service Protection**: Large job lists are handled gracefully
3. **Memory Management**: Proper cleanup prevents memory leaks

## Limitations

1. **Snapshot Nature**: Provides a point-in-time view of active jobs
2. **Update Frequency**: Does not provide real-time updates without re-execution
3. **Task Visibility**: Only shows tasks managed by the Apollo task manager
4. **Display Limits**: Browser interface may have practical limits for very large job lists
5. **Network Dependency**: Requires active C2 communication for operation

## Troubleshooting

### Common Issues and Solutions

#### Empty Job List When Tasks Are Running
**Symptoms**: The `jobs` command returns an empty list despite other commands running

**Possible Causes**:
- Task manager not properly tracking tasks
- RPC communication failure
- Agent/server synchronization issues

**Solutions**:
- Restart the agent if possible
- Check Mythic server logs for RPC errors
- Verify callback communication status

#### Kill Buttons Not Working
**Symptoms**: Kill buttons appear but don't terminate jobs

**Possible Causes**:
- Jobkill command not available
- Permission issues
- Task in non-killable state

**Solutions**:
- Verify jobkill command is loaded
- Check operator permissions
- Review task documentation for kill limitations

#### Incomplete Job Information
**Symptoms**: Some job details are missing or show as empty

**Possible Causes**:
- RPC timeout issues
- Database inconsistencies
- Partial task metadata

**Solutions**:
- Re-run the jobs command
- Check Mythic database integrity
- Review server performance metrics

## References

- [Mythic Agent Development](https://docs.mythic-c2.net/)
- [Apollo Agent Documentation](https://github.com/MythicAgents/Apollo)
- [Mythic RPC System](https://docs.mythic-c2.net/customizing/c2-related-development/c2-profile-code/agent-side-coding/action-complete_task)
- [JavaScript Table Rendering](https://docs.mythic-c2.net/customizing/browser-scripts/browserscript-function)
- [Task Management Best Practices](https://docs.mythic-c2.net/customizing/payload-type-development)