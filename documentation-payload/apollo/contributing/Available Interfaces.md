+++
title = "Contributing"
chapter = true
weight = 25
pre = "<b>4. </b>"
+++

## Creating a New Profile

Profiles should be created as new .NET Framework 4.0 Class Library projects under the Apollo parent solution (see HttpProfile, NamedPipeProfile, TcpProfile as examples). Your new profile must use the ApolloInterop class library as a reference (prefereably as a Project reference). For the rest of this write-up, this new project will be called "SomeChannelProfile."

Once SomeChannelProfile has been created and ApolloInterop has been added as a reference, create a new file `SomeChannelProfile.cs`. The namespace may be arbitrary, but has followed the schema `namespace XyyyTransport` where `Xyyy` is the medium through which this profile communicates. So `HttpTransport`, `NamedPipeTransport`, etc. This file will implement a new class that inherits from the `C2Profile` abstract class and the `IC2Profile` interface. Below is a template for what `SomeChannelProfile.cs` might look like before it's been filled in.

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Types.Delegates;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using ApolloInterop.Enums.ApolloEnums;

namespace SomeChannelTransport
{
    public class SomeChannelProfile : C2Profile, IC2Profile
    {
        /*
         * Private variables to be tracked by the profile, such as configuration options.
        */

        // Internal tracking to determine if staging should be done again or not upon profile disconnect
        private bool _uuidNegotiated = false;

        /*
         * Dictionary<string, string> data : Profile options passed to the constructor of this profile (think URL, Host Header, Named Pipe Names, etc.)
         * ISerializer serializer : The serialization schema to use when wrapping Mythic messages. By default, this is an encrypted JSON serializer,
                                    meaning structs are packed as JSON blobs then encrypted with AES.
         * IAgent agent : IAgent is an interface that allows all parts of the agent to interface with one another. This is the dependency injection model
                          that Apollo follows. See the "Available Interfaces" documentation.
        */
        public SomeChannelProfile(Dictionary<string, string> data, ISerializer serializer, IAgent agent) : base(data, serializer, agent)
        {
            // Initialize profile variables
        }

        // The main working function. Once the profile is connected, this should initiate the main tasking loop.
        public void Start()
        {

        }


        // This retrieves the Tasking messages from the agent. Over time, the agent will accumulate task responses
        // to send to Mythic. The Profile should contact the agent for messages and process them onward.
        // Once tasking has been retrieved, call the OnResponse delegate.
        private bool GetTasking(OnResponse<MessageResponse> onResp)
        {
            
        }


        // Used to determine if this profile is a dead-drop or a two-way communication.
        // Unused. Reserved.
        public bool IsOneWay()
        {
            
        }

        // Used if the profile is a one way profile. Useful when the data being sent will not receive
        // a response.
        public bool Send<T>(T message)
        {

        }

        // Used if the profile is a one way profile. Retrieve the results of the previous Send<T> call.
        // When results are retrieved, call OnResponse delegate.
        public bool Recv<T>(OnResponse<T> onResponse)
        {

        }

        // Used if the profile is a one way profile. Retrieve the results of the previous Send<T> call. 
        public bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp)
        {
            throw new NotImplementedException("HttpProfile does not support Recv only.");
        }

        // Send a message to Mythic and retrieve the results. Once the results are returned, caller should
        // invoke the OnResponse function.
        public bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse)
        {
            
            
        }

        // Used to initialize the profile. In the case of reverse connect profiles, like HTTP, there is nothing to do.
        // Other times, profiles may need to do initial boot here.
        public bool Connect()
        {

        }

        // Returns if the profile is currently communicating to Mythic in some capacity (via direct, indirect, through peers, etc.)
        public bool IsConnected()
        {

        }

        // Connect to Mythic given the specified CheckinMessage. This should handle any EKE, and when it connects
        // to Mythic successfully (e.g., stages fully on EKE, etc.) call the OnResponse delegate.
        public bool Connect(CheckinMessage checkinMsg, OnResponse<MessageResponse> onResp)
        {
            
        }

    }
}
```

Once you have a draft of `SomeChannelProfile` complete, in the `Apollo` project, add the `SomeChannelProfile` project as a reference. Then, in the file `Apollo/Config.cs`, add the following:

```
#define C2PROFILE_NAME_UPPER

#if DEBUG
#define HTTP
#endif

using HttpTransport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ApolloInterop.Structs.ApolloStructs;
using PSKCryptography;
using ApolloInterop.Serializers;
using NamedPipeTransport;
using TcpTransport;

namespace Apollo
{
    public static class Config
    {
        public static Dictionary<string, C2ProfileData> EgressProfiles = new Dictionary<string, C2ProfileData>()
        {
            ... other parameter definitions ...
#elif SOMECHANNEL
            { "somechannel", new C2ProfileData()
                {
                    TC2Profile = typeof(SomeChannelProfile),
                    TCryptography = typeof(PSKCryptographyProvider), // the default
                    TSerializer = typeof(EncryptedJsonSerializer),   // the default
                    Parameters = new Dictionary<string, string>()
                    {
#if DEBUG
                        // Used to auto-initialize debug variables for your profile to troubleshoot
                        { "param1", "debug_value1" },
                        { "param2", "debug_value2" },
#else
                        { "param1", "param1_value" },
                        { "param2", "param1_value" },
#endif
                    }
                }
            }
#endif
        };


        public static Dictionary<string, C2ProfileData> IngressProfiles = new Dictionary<string, C2ProfileData>();
#if DEBUG
... debug AESPSKs for various profiles...
#elif SOMECHANNEL
        public static string StagingRSAPrivateKey = "SomeAgentKeyToDebugHere";
#endif
... debug payload UUIDs for other profiles ...
#elif SOMECHANNEL
        public static string PayloadUUID = "AgentDebugUUIDHere";
#endif
#else
        ... do not change release settings ...
#endif
    }
}

```