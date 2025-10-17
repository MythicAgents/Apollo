+++
title = "HTTPX"
chapter = false
weight = 103
+++

## Summary
Advanced HTTP profile with malleable configuration support and message transforms for enhanced OPSEC. Based on the httpx C2 profile with extensive customization options.

### Profile Options

#### Callback Domains
Array of callback domains to communicate with. Supports multiple domains for redundancy and domain rotation.

**Example:** `https://example.com:443,https://backup.com:443`

#### Domain Rotation
Domain rotation pattern for handling multiple callback domains:

- **fail-over**: Uses each domain in order until communication fails, then moves to the next
- **round-robin**: Cycles through domains for each request
- **random**: Randomly selects a domain for each request

#### Failover Threshold
Number of consecutive failures before switching to the next domain in fail-over mode.

**Default:** 5

#### Callback Interval in seconds
Time to sleep between agent check-ins.

**Default:** 10

#### Callback Jitter in percent
Randomize the callback interval within the specified threshold.

**Default:** 23

#### Encrypted Exchange Check
Perform encrypted key exchange with Mythic on check-in. Recommended to keep as true.

**Default:** true

#### Kill Date
The date at which the agent will stop calling back.

**Default:** 365 days from build

#### Raw C2 Config
JSON configuration file defining malleable profile behavior. If not provided, uses default configuration.

### proxy_host
Proxy server hostname or IP address for outbound connections.

**Example:** `proxy.company.com`

### proxy_port
Proxy server port number.

**Example:** `8080`

### proxy_user
Username for proxy authentication (if required).

### proxy_pass
Password for proxy authentication (if required).

### domain_front
Domain fronting header value. Sets the `Host` header to this value for traffic obfuscation.

**Example:** `cdn.example.com`

### timeout
Request timeout in seconds for HTTP connections.

**Default:** `240`

## Malleable Profile Configuration

The httpx profile supports extensive customization through malleable profiles defined in JSON format.

### Configuration Structure

```json
{
    "name": "Profile Name",
    "get": {
        "verb": "GET",
        "uris": ["/api/status", "/health"],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            },
            "parameters": {
                "version": "1.0",
                "format": "json"
            },
            "message": {
                "location": "query",
                "name": "data"
            },
            "transforms": [
                {
                    "action": "base64",
                    "value": ""
                }
            ]
        },
        "server": {
            "headers": {
                "Content-Type": "application/json",
                "Server": "nginx/1.18.0"
            },
            "transforms": [
                {
                    "action": "base64",
                    "value": ""
                }
            ]
        }
    },
    "post": {
        "verb": "POST",
        "uris": ["/api/data", "/submit"],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "message": {
                "location": "body",
                "name": ""
            },
            "transforms": [
                {
                    "action": "base64",
                    "value": ""
                }
            ]
        },
        "server": {
            "headers": {
                "Content-Type": "application/json",
                "Server": "nginx/1.18.0"
            },
            "transforms": [
                {
                    "action": "base64",
                    "value": ""
                }
            ]
        }
    }
}
```

### Message Locations

Messages can be placed in different parts of HTTP requests:

- **body**: Message in request body (default for POST)
- **query**: Message as query parameter
- **header**: Message in HTTP header
- **cookie**: Message in HTTP cookie

### Transform Actions

The following transform actions are supported:

#### base64
Standard Base64 encoding/decoding.

#### base64url
URL-safe Base64 encoding/decoding (uses `-` and `_` instead of `+` and `/`).

#### netbios
NetBIOS encoding (lowercase). Each byte is split into two nibbles and encoded as lowercase letters.

#### netbiosu
NetBIOS encoding (uppercase). Each byte is split into two nibbles and encoded as uppercase letters.

#### xor
XOR encryption with specified key.

**Example:**
```json
{
    "action": "xor",
    "value": "mysecretkey"
}
```

#### prepend
Prepend data with specified value.

**Example:**
```json
{
    "action": "prepend",
    "value": "prefix"
}
```

#### append
Append data with specified value.

**Example:**
```json
{
    "action": "append",
    "value": "suffix"
}
```

### Transform Chains

Transforms are applied in sequence. For client transforms, they are applied in order. For server transforms, they are applied in reverse order to decode the data.

**Example Transform Chain:**
```json
"transforms": [
    {
        "action": "xor",
        "value": "secretkey"
    },
    {
        "action": "base64",
        "value": ""
    },
    {
        "action": "prepend",
        "value": "data="
    }
]
```

## Example Malleable Profiles

### Microsoft Update Profile
```json
{
    "name": "Microsoft Update",
    "get": {
        "verb": "GET",
        "uris": [
            "/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
            "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab"
        ],
        "client": {
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "Keep-Alive",
                "Cache-Control": "no-cache",
                "User-Agent": "Microsoft-CryptoAPI/10.0"
            },
            "parameters": null,
            "message": {
                "location": "query",
                "name": "cversion"
            },
            "transforms": [
                {
                    "action": "base64url",
                    "value": ""
                }
            ]
        },
        "server": {
            "headers": {
                "Content-Type": "application/vnd.ms-cab-compressed",
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET",
                "Connection": "keep-alive",
                "Cache-Control": "max-age=86400"
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "updateKey2025"
                },
                {
                    "action": "base64",
                    "value": ""
                },
                {
                    "action": "prepend",
                    "value": "MSCF\u0000\u0000\u0000\u0000"
                },
                {
                    "action": "append",
                    "value": "\u0000\u0000\u0001\u0000\u0000\u0000\u0000\u0000"
                }
            ]
        }
    },
    "post": {
        "verb": "POST",
        "uris": [
            "/msdownload/update/v3/static/feedbackapi/en/feedback.aspx"
        ],
        "client": {
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Microsoft-CryptoAPI/10.0"
            },
            "parameters": null,
            "message": {
                "location": "body",
                "name": "feedback"
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "feedbackKey"
                },
                {
                    "action": "base64",
                    "value": ""
                }
            ]
        },
        "server": {
            "headers": {
                "Content-Type": "text/html; charset=utf-8",
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET",
                "Connection": "keep-alive",
                "Cache-Control": "no-cache, no-store"
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "responseKey"
                },
                {
                    "action": "base64",
                    "value": ""
                },
                {
                    "action": "prepend",
                    "value": "<!DOCTYPE html><html><head><title>Feedback Submitted</title></head><body><div>"
                },
                {
                    "action": "append",
                    "value": "</div><script>setTimeout(function(){window.location.href='https://www.microsoft.com';},500);</script></body></html>"
                }
            ]
        }
    }
}
```

### jQuery CDN Profile
```json
{
    "name": "jQuery CDN",
    "get": {
        "verb": "GET",
        "uris": [
            "/jquery-3.3.0.min.js"
        ],
        "client": {
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "Keep-Alive",
                "Keep-Alive": "timeout=10, max=100",
                "Referer": "http://code.jquery.com/",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
            },
            "parameters": null,
            "message": {
                "location": "cookie",
                "name": "__cfduid"
            },
            "transforms": [
                {
                    "action": "base64url",
                    "value": ""
                }
            ]
        },
        "server": {
            "headers": {
                "Cache-Control": "max-age=0, no-cache",
                "Connection": "keep-alive",
                "Content-Type": "application/javascript; charset=utf-8",
                "Pragma": "no-cache",
                "Server": "NetDNA-cache/2.2"
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "randomKey"
                },
                {
                    "action": "base64",
                    "value": ""
                },
                {
                    "action": "prepend",
                    "value": "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */"
                },
                {
                    "action": "append",
                    "value": "\".(o=t.documentElement,Math.max(t.body[\"scroll\"+e],o[\"scroll\"+e],t.body[\"offset\"+e],o[\"offset\"+e],o[\"client\"+e])):void 0===i?w.css(t,n,s):w.style(t,n,i,s)},t,a?i:void 0,a)}})}),w.each(\"blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu\".split(\" \"),function(e,t){w.fn[t]=function(e,n){return arguments.length>0?this.on(t,null,e,n):this.trigger(t)}}),w.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),w.fn.extend({bind:function(e,t,n){return this.on(e,null,t,n)},unbind:function(e,t){return this.off(e,null,t)},delegate:function(e,t,n,r){return this.on(t,e,n,r)},undelegate:function(e,t,n){return 1===arguments.length?this.off(e,\"**\"):this.off(t,e||\"**\",n)}}),w.proxy=function(e,t){var n,r,i;if(\"string\"==typeof t&&(n=e[t],t=e,e=n),g(e))return r=o.call(arguments,2),i=function(){return e.apply(t||this,r.concat(o.call(arguments)))},i.guid=e.guid=e.guid||w.guid++,i},w.holdReady=function(e){e?w.readyWait++:w.ready(!0)},w.isArray=Array.isArray,w.parseJSON=JSON.parse,w.nodeName=N,w.isFunction=g,w.isWindow=y,w.camelCase=G,w.type=x,w.now=Date.now,w.isNumeric=function(e){var t=w.type(e);return(\"number\"===t||\"string\"===t)&&!isNaN(e-parseFloat(e))},\"function\"==typeof define&&define.amd&&define(\"jquery\",[],function(){return w});var Jt=e.jQuery,Kt=e.$;return w.noConflict=function(t){return e.$===w&&(e.$=Kt),t&&e.jQuery===w&&(e.jQuery=Jt),w},t||(e.jQuery=e.$=w),w});"
                }
            ]
        }
    },
    "post": {
        "verb": "POST",
        "uris": [
            "/jquery-3.3.0.min.js"
        ],
        "client": {
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Referer": "http://code.jquery.com/",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
            },
            "parameters": null,
            "message": {
                "location": "body",
                "name": ""
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "someOtherRandomKey"
                }
            ]
        },
        "server": {
            "headers": {
                "Cache-Control": "max-age=0, no-cache",
                "Connection": "keep-alive",
                "Content-Type": "application/javascript; charset=utf-8",
                "Pragma": "no-cache",
                "Server": "NetDNA-cache/2.2"
            },
            "transforms": [
                {
                    "action": "xor",
                    "value": "yetAnotherSomeRandomKey"
                },
                {
                    "action": "base64",
                    "value": ""
                },
                {
                    "action": "prepend",
                    "value": "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */"
                },
                {
                    "action": "append",
                    "value": "\".(o=t.documentElement,Math.max(t.body[\"scroll\"+e],o[\"scroll\"+e],t.body[\"offset\"+e],o[\"offset\"+e],o[\"client\"+e])):void 0===i?w.css(t,n,s):w.style(t,n,i,s)},t,a?i:void 0,a)}})}),w.each(\"blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu\".split(\" \"),function(e,t){w.fn[t]=function(e,n){return arguments.length>0?this.on(t,null,e,n):this.trigger(t)}}),w.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),w.fn.extend({bind:function(e,t,n){return this.on(e,null,t,n)},unbind:function(e,t){return this.off(e,null,t)},delegate:function(e,t,n,r){return this.on(t,e,n,r)},undelegate:function(e,t,n){return 1===arguments.length?this.off(e,\"**\"):this.off(t,e||\"**\",n)}}),w.proxy=function(e,t){var n,r,i;if(\"string\"==typeof t&&(n=e[t],t=e,e=n),g(e))return r=o.call(arguments,2),i=function(){return e.apply(t||this,r.concat(o.call(arguments)))},i.guid=e.guid=e.guid||w.guid++,i},w.holdReady=function(e){e?w.readyWait++:w.ready(!0)},w.isArray=Array.isArray,w.parseJSON=JSON.parse,w.nodeName=N,w.isFunction=g,w.isWindow=y,w.camelCase=G,w.type=x,w.now=Date.now,w.isNumeric=function(e){var t=w.type(e);return(\"number\"===t||\"string\"===t)&&!isNaN(e-parseFloat(e))},\"function\"==typeof define&&define.amd&&define(\"jquery\",[],function(){return w});var Jt=e.jQuery,Kt=e.$;return w.noConflict=function(t){return e.$===w&&(e.$=Kt),t&&e.jQuery===w&&(e.jQuery=Jt),w},t||(e.jQuery=e.$=w),w});"
                }
            ]
        }
    }
}
```

## Migration from HTTP Profile

To migrate from the basic HTTP profile to httpx:

1. **Update C2 Profile**: Change from "http" to "httpx" in your payload configuration
2. **Configure Domains**: Set callback domains instead of single callback host
3. **Add Malleable Profile**: Upload a JSON configuration file via the "Raw C2 Config" parameter
4. **Test Configuration**: Verify the profile works with your infrastructure

## OPSEC Considerations

- Use realistic User-Agent strings that match your target environment
- Choose URIs that blend with legitimate traffic patterns
- Implement appropriate transforms to obfuscate communication
- Consider domain rotation for redundancy and evasion
- Test profiles against network monitoring tools
- Use HTTPS endpoints when possible
- Implement proper error handling and fallback mechanisms

## Troubleshooting

### Common Issues

1. **Transform Errors**: Ensure transform chains are properly configured and reversible
2. **Domain Resolution**: Verify all callback domains are accessible
3. **Profile Validation**: Check JSON syntax and required fields
4. **Header Conflicts**: Avoid conflicting or invalid HTTP headers

### Debug Tips

- Start with simple base64 transforms before adding complex chains
- Test profiles with small payloads first
- Use network monitoring tools to verify traffic patterns
- Check server logs for any configuration issues
