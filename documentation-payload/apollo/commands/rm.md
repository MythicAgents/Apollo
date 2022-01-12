+++
title = "rm"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Artifacts Generated: File Delete
{{% /notice %}}

## Summary
Delete a specified file.

### Arguments (Positional)
#### Path
Path to a the file to be deleted. If this is not a full path, the agent's current working directory will be used. 

## Usage
```
rm [path]
rm -Path [path]
```
Example
```
rm C:\config.txt
rm -Path C:\Program Files\Google Chrome
```

## MITRE ATT&CK Mapping

- T1106
- T1107