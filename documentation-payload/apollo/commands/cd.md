+++
title = "cd"
chapter = false
weight = 103
hidden = true
+++

## Summary
Change the process's current working directory to a specified directory. This command accepts relative paths such as `..\` as well.

## Arguments

![args](../images/cd.png)

### Path
Change to the directory specified by path.

## Usage
```
cd -Path [path]
cd [path]
```
Example
```
cd -Path C:\Users
```
Change to the root directory.
```
cd C:\
```
Change to the previous level directory.
```
cd ..
```
Change to a directory with spaces in name.
```
cd C:\Program Files
```

## MITRE ATT&CK Mapping

- T1083

## Detailed Summary
The `cd` command uses the `System.IO.Directory.SetCurrentDirectory` method to modify the process's current working directory to a specified directory. This command accepts relative paths, such as `..` or `..\..\Users`. Quotes are not needed when changing to directories with _spaces_ in their path name, such as `C:\Program Files`.

