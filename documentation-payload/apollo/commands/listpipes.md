+++
title = "listpipes"
chapter = false
weight = 150
hidden = false
+++

## Summary
The `listpipes` function enumerates all named pipes on the local Windows host using the `FindFirstFileW` API on the `\\.\\pipe\\*` namespace. Named pipes are commonly used for inter-process communication (IPC), and this function helps discover active communication endpoints used by system services, applications, or malicious software.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @ToweringDragoon

### Arguments
This command takes no arguments.

## Usage
### Example: Listing Named Pipes on the Local Machine
**Command:**
```c
listpipes
```

**Output:**
```plaintext
Found 56 named pipes:
InitShutdown
lsass
ntsvcs
scerpc
spoolss
wkssvc
srvsvc
...
```

## MITRE ATT&CK Mapping
- **T1083** - File and Directory Discovery (As named pipes are part of the Windows object namespace)

## Detailed Summary
The `listpipes` task queries the Windows named pipe namespace using the `FindFirstFileW("\\\\.\\pipe\\*")` API. This method allows the agent to list active named pipe objects from user mode without relying on NT Native API calls like `NtQueryDirectoryObject`, which often fail or require elevated access.

### Functional Steps:

1. **Initialize Pipe Search:**
   - Calls `FindFirstFileW("\\.\\pipe\\*")` to begin enumeration of named pipe objects.

2. **Iterate Through Pipe Names:**
   - Uses `FindNextFileW` in a loop to collect all entries under the `\\.\\pipe\\` namespace.

3. **Filter Results:**
   - Trims null terminators.
   - Filters out invalid or malformed names (though the default implementation includes everything unless manually filtered).

4. **Return Results:**
   - Aggregates all valid pipe names and returns a summary string in the format: `Found X named pipes:` followed by newline-separated pipe names.

5. **Error Handling:**
   - If `FindFirstFileW` fails, the function throws an exception with the associated Win32 error code.

## APIs Used and Their Purposes
| API | Purpose | DLL | Documentation |
|------|---------|-----|--------------|
| `FindFirstFileW` | Begins enumeration of pipe names under `\\.\\pipe\\` | kernel32.dll | [FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew) |
| `FindNextFileW` | Continues enumeration of named pipes | kernel32.dll | [FindNextFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew) |
| `FindClose` | Closes the pipe enumeration handle | kernel32.dll | [FindClose](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findclose) |
| `Marshal.GetLastWin32Error` | Captures last error code after Win32 API failure | mscorlib.dll | [GetLastWin32Error](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getlastwin32error) |

## Considerations
- **Permissions:** This command does not require administrative privileges. However, access to specific pipes may still be restricted based on ACLs.
- **OPSEC:** Enumerating named pipes may cause suspicious handle access logs to appear in security monitoring tools or EDRs.
- **Performance:** This is a lightweight operation and generally completes quickly unless the system has an extremely large number of named pipes.

## References
- [Windows Named Pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes)
- [NT Object Namespace](https://learn.microsoft.com/en-us/windows/win32/sysinfo/object-namespaces)
- [Sysinternals PipeList Tool](https://learn.microsoft.com/en-us/sysinternals/downloads/pipelist)