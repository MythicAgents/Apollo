+++
title = "cp"
chapter = false
weight = 103
hidden = true
+++

{{% notice info %}}
### Artifacts
- File Open
- File Write
{{% /notice %}}

## Summary
Copy a specified file to another location.

### Arguments

![args](../images/cp.png)

#### Destination
The path to copy a file too.

#### Source File
The path to the original file that will be copied and placed in the location specified by `Destination`.

## Usage
```
cp -Path [source] -Destination [destination]
```
Example
```
cp -Path test1.txt -Destination "C:\Program Files\test2.txt"
```

## MITRE ATT&CK Mapping

- T1570

## Detailed Summary
The `cp` command uses the `System.IO.File.Copy` method to copy a file from a source path to a destination path. This command accepts UNC paths for file copies. 