+++
title = "download"
chapter = false
weight = 103
hidden = true
+++

## Summary
Download a specified file from the agent's host to the Mythic server.

### Arguments (Positional)
#### path

Path to the file to download.

## Usage
```
download [path to file]
```
Example
```
download C:\Users\user\Downloads\test.txt

download [modal popup]

From the file browser, Actions -> Task a Download
```

When a download is in progress, you'll see that the download has started but is incomplete.

![download1](../images/download01.png)

When the download completes, clicking the link will automatically download the file to your Downloads folder.

![download2](../images/download02.png)


## MITRE ATT&CK Mapping

- T1020
- T1030
- T1041

## Detailed Summary
The `download` command uses a `FileStream` to collect `512KB` chunks of a file  as `Base64` strings and send each chunk back to the Mythic server to download a specified file. Files downloaded from agents are available for download from the Mythic server by navigating to `Operational Views` -> `Files`. Specifying a file name without a full path will search for the file in the current working directory. UNC paths are also acceptable for downloads.

Alternatively, one may download the file directly from the UI once the download is complete.