+++
title = "mv"
chapter = false
weight = 103
hidden = false
+++

## Summary
Move a specified file to another location.

### Arguments (modal popup)
#### destiantion
The path to move a file too.

#### source
The path to the original file to be moved.

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

## Detailed Usage
Move a file to a UNC path
```
mv
```
In the pop up menu
```
destination: C:\config.txt
source: \\server1\C$\Windows\Temp\config.txt
```
