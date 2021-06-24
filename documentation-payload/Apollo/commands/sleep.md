+++
title = "sleep"
chapter = false
weight = 103
hidden = true
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

## Detailed Summary
The `sleep` command uses the `Thread.Sleep` method to "sleep" the agent for the set sleep time. This allows asynchronous callbacks to the Mythic server to reduce network traffic. A jitter effect can also be applied, in which a percentage of the `sleep` time will be added and subtracted to the time and a random number in this range will be selected. This gives randomness to the agent's sleep time. A sleep time of `0` will be Continuously calling back to the Mythic server and is considered `Interactive` mode for the agent.
