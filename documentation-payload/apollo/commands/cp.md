+++
title = "cp"
chapter = false
weight = 103
hidden = false
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

#### Path
The path to the original file that will be copied and placed in the location specified by `Destination`.

#### Destination
The path to copy a file too.

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