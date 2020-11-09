+++
title = "HTTP"
chapter = false
weight = 102
+++

## Summary
The `Apollo` agent uses a series of `POST` web requests to send responses for tasking and a single `GET` request to retrieve taskings.

### Profile Option Deviations

#### GET Request URI and POST Request URI

Currently the agent does not support these parameters and will callback always to `callback_host:callback_port/api/v1.4/agent_message`

#### Callback Host
The URL for the redirector or Mythic server. This must include the protocol to use (e.g. `http://` or `https://`). 