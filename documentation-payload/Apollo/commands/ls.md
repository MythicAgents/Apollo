+++
title = "ls"
chapter = false
weight = 103
hidden = false
+++

## Summary
List files and folders in a specified directory. This will also populate Mythic's file browser cache.

### Arguments (positional)
#### path
Specify what path you want to list the contents of. If not specified, this will default to the current working directory. This parameter also accepts UNC paths, such as `\\DC01\C$`

## Usage
```
ls [path]
```

## Detailed Summary
The `ls` command retrieves information about files and folders within a specified directory. This information is collected with multiple methods from the `System.IO.File` and `System.IO.Directory` classes. Information gathered includes name, size, last accessed date, last modified date, object owner, an object's hidden status, and a parsed access control list for the object.

Below shows the results of issuing an `ls` command with no parameters.

![ls from command line](../images/ls01.png)

When clicking on the three-users icon under the "Permissions" tab, you'll see the associated ACLs for that file.

![ACLs for an object](../images/ls02.png)

This command is also integrated into the Mythic file browser.

![File browser](../images/ls03.png)