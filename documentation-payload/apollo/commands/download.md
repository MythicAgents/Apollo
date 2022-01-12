+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: File Open
{{% /notice %}}

## Summary
Download a specified file from the agent's host to the Mythic server.

### Arguments (Positional)
#### Path

Path to the file to download.

#### Host (optional)

Host to download the file from. Default: localhost.

## Usage
```
download -Path [path to file] [-Host [127.0.0.1]]
```
Example
```
download -Path C:\Users\user\Downloads\test.txt

download -Path C:\Users\user\Downloads\test.txt -Host 127.0.0.1

From the file browser, Actions -> Task a Download
```

When the download completes, clicking the link will automatically download the file to your Downloads folder.

![download2](../images/download02.png)


## MITRE ATT&CK Mapping

- T1020
- T1030
- T1041