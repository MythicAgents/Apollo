+++
title = "ls"
chapter = false
weight = 103
hidden = false
+++

## Summary
List files and folders in a specified directory. This will also populate Mythic's file browser cache.

### Arguments (Positional)
#### path
Specify what path you want to list the contents of. If not specified, this will default to the current working directory. This parameter also accepts UNC paths, such as `\\DC01\C$`

## Usage
```
ls [path]
```

## Example
![ls from command line](../images/ls01.png)

When clicking on the three-users icon under the "Permissions" tab, you'll see the associated ACLs for that file.

![ACLs for an object](../images/ls02.png)

This command is also integrated into the Mythic file browser.

![File browser](../images/filebrowser.png)


## MITRE ATT&CK Mapping

- T1106
- T1083