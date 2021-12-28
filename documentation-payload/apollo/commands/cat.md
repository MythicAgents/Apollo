+++
title = "cat"
chapter = false
weight = 103
hidden = true
+++

## Summary

Print the contents of a file.

### Arguments
![args](../images/cat.png)
#### Path
Specify path to file to read contents

## Usage
```
cat -Path [path]
```
Example
```
cat -Path C:\config.txt
cat C:\config.txt
```

## MITRE ATT&CK Mapping

- T1081
- T1106

## Detailed Summary
The `cat` command streams output back to Mythic reading 256kb of a file at a time.