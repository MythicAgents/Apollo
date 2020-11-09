+++
title = "upload"
chapter = false
weight = 103
hidden = false
+++

## Summary
Upload a file from the Mythic server to the remote host.

### Arguments (modal popup)
#### file
File browser to select local file to be uploaded.

#### remote_path
The path to upload the file too. UNC paths are acceptable.

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

## Detailed Summary
The `upload` command recieves `512kb` chunks of a file from the Mythic server and saves those to the specified file path. If the file exist, the command will return an error.
