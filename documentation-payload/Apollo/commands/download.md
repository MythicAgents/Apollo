+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

## Summary
Download a specified file from the agent's host to the Mythic server.

### Arguments (positional)
#### path
Specify path to file.

## Usage
```
download [path to file]
```
Example
```
download [path to file]
```

## Detailed Summary
The `download` command uses a `FileStream` to collect `512KB` chunks of a file  as `Base64` strings and send each chunk back to the Mythic server to download a specified file. Files downloaded from agents are available for download from the Mythic server by navigating to `Operational Views` -> `Files`. Specifying a file name without a full path will search for the file in the current working directory. UNC paths are also acceptable for downloads.

Alternatively, one may download the file directly from the UI once downloaded as shown below.

![alt text](../images/download.png)
