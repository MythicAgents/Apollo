+++
title = "sleep"
chapter = false
weight = 103
hidden = false
+++

## Summary
Change the agent's callback interval in seconds. Optionally specify the agent's jitter percentage for callback intervals.

### Arguments (Positional)
#### interval 
The amount of time an agent will wait before callback to the Mythic server in _seconds_.

#### jitter
A percentage value to randomize callback intervals for a randomness effect. Valid inputs will be between `0` and `99`.

## Usage
```
sleep [seconds] [jitter]
```
Example
```
sleep 60 25
```


## MITRE ATT&CK Mapping

- T1029