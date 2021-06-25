+++
title = "bypassuac"
chapter = false
weight = 103
hidden = true
+++

## Summary

Bypasses user account control (UAC) to spawn an elevated agent using "mock" trusted directory technique, as outlined (here)[https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e] by David Wells from Tenable security.

### Arguments (Popup)

![popup](../images/bypassuac01.png)

#### payload
Select the payload template to use with the bypass. Payload templates are generated whenever a new payload is created from the `Create Components > Create Payload` menu.

#### targetArgs
Any arguments to be passed to the payload. This is only required should you run a command that is not a new agent.

#### targetPath
Location to save payload too. By default, the executable is saved to `%TEMP%\RANDOMLY-GENERATED-UUID-HERE.exe`

## Usage
```
bypassuac
```
In pop up menu
```
payload: [payload to use]
targetArgs: [arguments for payload]
targetPath: [path to save payload]
```
Example
```
bypassuac
```
In pop up menu
```
payload: Apollo - HTTP,SMBServer
targetArgs:
targetPath: C:\Windows \System32\cmd.exe
```

![bypassuac](../images/bypassuac02.png)

## MITRE ATT&CK Mapping

- T1548

## Detailed Summary
The `bypassuac` command uses a "mock" directory method to bypass User Access Control and execute a payload in a high integirty context. This implementaion creates the directory `C:\Windows \System32` and copy the `winSAT.exe` utility to this directory. `winSAT.exe` will be exeucted and use Window's _Auto Elevate_ function to execute in a high integrity. To get code execution, a loader will be saved as `winmm.dll` in this directory and be loaded by `winSAT.exe` upon execution via a Dll hijack. This loader program will execute the specified agent payload using `cmd.exe` granting an agent callback in high integrity. 

### Resources
- [Tenable](https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e)
- [MockDirUACBypass](https://github.com/matterpreter/OffensiveCSharp/tree/master/MockDirUACBypass)
