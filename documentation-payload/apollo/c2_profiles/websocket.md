+++
title = "websocket"
chapter = false
weight = 102
+++

## Summary
The `Apollo` agent can use websockets to support getting tasks and returning task data. The profile supports both `Poll`and `Push` tasking types. System proxies are supported.

### Profile Options

#### Tasking type

Choose between Poll (periodic check-ins like HTTPS profiles) or Push tasking types. Push is recommended.

#### Callback Host
The URL for websocket redirector or Mythic server. This must include the protocol to use (e.g. `ws://` or `wss://`).

#### Callback Interval in seconds
Time to sleep between agent check-in, only relevant for the `Poll` tasking type.

#### Callback Jitter in percent
Randomize the callback interval within the specified threshold. e.g., if Callback Interval is 10, and jitter is 20, Apollo will call back randomly along the interval 8 and 12 seconds. Only relevant for the `Poll` tasking type.

#### Callback Port
The port at which the web server Apollo reaches out to lives on (80, 443, etc.)

#### Crypto type
Do not modify from aes256_hmac.

#### Host header
The Host header for the initial HTTP request, can be used to support domain fronting.

#### Kill Date
The date at which the agent will stop calling back.

#### Performs Key Exchange
Perform encrypted key exchange with Mythic on check-in. Recommended to keep as T for true.

#### User Agent
Provide a custom user agent used in the initial HTTP request in order to set up the websocket.

#### Websockets Endpoint
The endpoint used for the initial upgrading of the HTTP connection to websockets.