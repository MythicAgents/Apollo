+++
title = "HTTP"
chapter = false
weight = 102
+++

## Summary
The `Apollo` agent uses a series of `POST` web requests to send responses for tasking and a single `GET` request to retrieve taskings.

### Profile Option Deviations

#### GET Requests 

Currently the agent does not support any parameters in regards to GET parameters.

#### Callback Host
The URL for the redirector or Mythic server. This must include the protocol to use (e.g. `http://` or `https://`).

#### Proxy Host
If specified, must be of the same format as the Callback Host (e.g., `http://proxy.gateway`)

#### AESPSK
If the AESPSK is blank, the agent will not be able to communicate with the server.