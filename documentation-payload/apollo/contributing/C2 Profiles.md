+++
title = "Creating C2 Profiles"
chapter = false
weight = 25
+++

## Creating a New Profile

New command-and-control profiles for Apollo should be new projects under the Apollo solution. Your new project should be named `C2ChannelProfile`, where `C2Channel` is the means through which the profile will talk to Mythic. For example, if this profile communicates over HTTP, the project name will be `HttpProfile`. If it would communicate over web sockets, the name should be `WebSocketProfile`. This project should be a .NET Framework 4.0 Class library.

In your new project, create a class that has the same name as your project (e.g., `public class C2ChannelProfile`). This class should inherit from the `C2Profile` abstract class and the `IC2Profile` interface. The constructor of your new C2 profile will take the following parameters:

- Dictionary<string, string> parameters - C2 Profile specific parameters. For example, things like jitter, urls, host headers, etc. would all be passed via key-value pairs in this dictionary.
- ISerializer serializer - This object is used to prepare C# structures into a serialized format that Mythic will receive, and allow the profile to deserialize JSON messages from Mythic into Apollo structures. Currently this variable should not be modified in the agent core.
- IAgent agent - Core Apollo agent interface that grants the C2 profile access to other parts of the agent, such as the task manager.

The new C2 profile should implement the IC2Profile interface, which is as follows:

```
public interface IC2Profile
{
    // Used to connect to Mythic. This function will send the checkinMessage and perform any EKE, if required.
    //  On successful connect, this function will return the value of the onResp function.
    bool Connect(CheckinMessage checkinMessage, OnResponse<MessageResponse> onResp);

    // The main working loop of the agent. This should perform the periodic checkin of the agent,
    // dispatch new taskings, and return results.
    void Start();

    // If the profile, on submission of data, will not receive Mythic's response as a reply,
    // this function should be used. Example: The data is submitted to a separate url than
    // where Apollo will receive the response. Used if a one way profile.
    bool Send<IMythicMessage>(IMythicMessage message);

    // Send the data specified by Message to the server and pass the response of
    // Mythic ot the onResponse function.
    bool SendRecv<T, TResult>(T message, OnResponse<TResult> onResponse);

    // Fetch data from Mythic. Used if the profile is a one-way profile.
    bool Recv(MessageType mt, OnResponse<IMythicMessage> onResp);

    // Tells the caller that this C2 profile is stateful,
    // and as such it supports only the SendRecv operation.
    bool IsOneWay();

    // Return whether or not the C2 profile is currently talking to Mythic
    bool IsConnected();
}
```

## Adding Your Profile to Apollo Core

Once you've created your new C2 profile, you'll need to add it to Apollo as a build option for C2 profiles.

In the Apollo project under the Apollo solution, add your new C2 profile as a project reference. Then, at the top of the `Apollo/Config.cs` file, add the following lines:

```
using System;
...
#if C2CHANNEL
using C2ChannelProfile;
#endif
```

Lastly, in the `EgressProfiles` dictionary, add a new entry for your C2 profile. It shoudl be of the format:
```
#if C2CHANNEL
{ "c2channel", new C2ProfileData()
    {
        TC2Profile = typeof(C2ChannelProfile),
        TCryptography = typeof(PSKCryptography), // do not change
        TSerializer = typeof(EncryptedJsonSerializer), // do not change
        Parameters = new Dictionary<string, string>()
        {
#if DEBUG
            "param1": "debug_val_1",
            "param2": "debug_val_2",
            ...
#else
            "param1": "param_boilerplate_to_be_filled_in_by_builder.py",
            "param2": "param_boilerplate_to_be_filled_in_by_builder.py",
            ...
#endif
        }
    }
}
```
To debug your C2 Profile, simply fill in the parameter values in the DEBUG block of your parameters, and add at the top of the file `#define C2CHANNEL` in the `#if DEBUG` block.


### Add to Builder.py

Lastly, you'll need to modify the builder.py file under `Payload_Type/apollo/mythic/agent_functions`. In that file, add your new profile to the `c2profiles` attribute under Apollo.