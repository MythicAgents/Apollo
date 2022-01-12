+++
title = "upload"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
Artifacts Generated: File Write
{{% /notice %}}

## Summary
Upload a file from the Mythic server to the remote host.

### Arguments (Popup)

![args](../images/upload.png)

#### File
File browser to select local file to be uploaded.

#### Destination
The path to upload the file too. UNC paths are acceptable.

#### Host
Host to upload the file to.

## Usage
```
upload
```
In the pop up menu
```
file: [file]
remote_path: [remote_path]
```
Example
```
upload
```
In the pop up menu
```
file: test.exe
remote_path: C:\Windows\Temp\test.exe
```

## MITRE ATT&CK Mapping

- T1132
- T1030
- T1105

## Detailed Summary
The `upload` command recieves `512kb` chunks of a file from the Mythic server and saves those to the specified file path. If the file exist, the command will return an error.

{{% notice info %}}
A File Create artifact is generated from this command.
{{% /notice %}}