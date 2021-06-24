+++
title = "rm"
chapter = false
weight = 103
hidden = true
+++

## Summary
Delete a specified file.

### Arguments (Positional)
#### path
Path to a the file to be deleted. If this is not a full path, the agent's current working directory will be used. 

## Usage
```
rm [path]
```
Example
```
rm C:\config.txt
```

## MITRE ATT&CK Mapping

- T1106
- T1107

## Detailed Summary
The `rm` command uses the `System.IO.File.Delete` method to attempt to delete a specified file.

{{% notice info %}}
A File Delete artifact is generated from this command.
{{% /notice %}}