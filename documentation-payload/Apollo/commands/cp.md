+++
title = "cp"
chapter = false
weight = 103
hidden = true
+++

## Summary
Copy a specified file to another location.

### Arguments (Positional or Popup)

![args](../images/cp01.png)

#### Destination
The path to copy a file too.

#### Source File
The path to the original file that will be copied and placed in the location specified by `Destination`.

## Usage
```
cp [source] [destination]
```
Example
```
cp test1.txt "C:\Program Files\test2.txt"
```

## Detailed Summary
The `cp` command uses the `System.IO.File.Copy` method to copy a file from a source path to a destination path. This command accepts UNC paths for file copies. 


{{% notice info %}}
A File Create artifact is generated with the MD5 of the file copied.
{{% /notice %}}