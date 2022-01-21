+++
title = "HTTP"
chapter = false
weight = 102
+++

## Summary
Basic profile to send and receive taskings from Mythic over the hyper text transfer protocol.

### Profile Options

#### GET Requests 

Currently the agent does not support any parameters in regards to GET parameters.

#### Callback Host
The URL for the redirector or Mythic server. This must include the protocol to use (e.g. `http://` or `https://`).

#### Callback Interval in seconds
Time to sleep between agent check-in.

#### Callback Jitter in percent
Randomize the callback interval within the specified threshold. e.g., if Callback Interval is 10, and jitter is 20, Apollo will call back randomly along the interval 8 and 12 seconds.

#### Callback Port
The port at which the web server Apollo reaches out to lives on (80, 443, etc.)

#### Crypto type
Do not modify from aes256_hmac

#### GET request URI
The path on the web server Apollo will talk to

#### HTTP Headers
A dictionary of key-value pairs Apollo will attempt to use in web requests. Of note, Domain Fronting does not work in this profile configuration due to the .NET object used to create web requests.

#### Kill Date
The date at which the agent will stop calling back.

#### Name of the query parameter for GET requests
The included URL parameter, if any, used in GET requests

#### Performs Key Exchange
Perform encrypted key exchange with Mythic on check-in. Recommended to keep as T for true.

#### Proxy Host
If specified, must be of the same format as the Callback Host (e.g., `http://proxy.gateway`)

#### Proxy Password
The password used to authenticate to Proxy Host.

#### Proxy Port
The port at which Proxy Host is served.

#### Proxy Username
The username used to authenticate to the Proxy Host.