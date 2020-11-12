+++
title = "mv"
chapter = false
weight = 103
hidden = true
+++

## Summary
Move a specified file to another location.

### Arguments (Positional or Popup)
#### Destination
The path to move the file to.

#### Source File
The path of the original file to be moved.

## Usage
```
mv
```
In the pop up menu
```
destination: [path to file]
source: [path to file]
```
Example
```
mv
```
In the pop up menu
```
destination: C:\config.txt
source: C:\Windows\Temp\config.txt
```

## Detailed Summary
The `mv` command uses the `System.IO.File.Move` method to movey a file from a source path to a destination path. This command accepts UNC paths for file moves.

{{% notice info %}}
A File Move artifact is generated with the MD5 of the file moved from this command.
{{% /notice %}}