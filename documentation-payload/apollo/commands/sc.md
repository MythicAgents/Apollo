+++
title = "sc"
chapter = false
weight = 103
hidden = false
+++

## Summary
.NET implementation of the Service Control Manager binary `sc.exe`.

### Arguments

The `sc` command has several different parameter groups based on the type of tasking you perform. The taskings are grouped based on whether you pass the following flags:

- `-Query`
- `-Start`
- `-Stop`
- `-Create`
- `-Delete`

### Query

![query](../images/sc_query.png)

#### Computer (optional)

The computer to query services on.

#### ServiceName (optional)

The name of the service to query.

#### DisplayName (optional)

The display name of the service to query.

### Start

![start](../images/sc_start.png)

#### ServiceName

The name of the service to start.

#### Computer (optional)

The computer on which the specified `ServiceName` will be started.

### Stop

![stop](../images/sc_stop.png)

#### ServiceName

The name of the service to stop.

#### Computer (optional)

The computer to stop the specified `ServiceName` service.

### Create

![create](../images/sc_create.png)

#### ServiceName

The name of the service that will be created.

#### DisplayName

The display name of the new service.

#### BinPath

Path to service executable.

#### Computer (optional)

Computer to create the service on.

### Delete

![delete](../images/sc_delete.png)

#### ServiceName

The name of the service to stop.

#### Computer (optional)

The computer to stop the specified `ServiceName` service.

## Usage
```
# Query services locally
sc -Query

# Start a service on a computer (requires admin)
sc -Start -ServiceName ApolloSvc -Computer DC1

# Stop a service
sc -Stop -ServiceName ApolloSvc

# Create a service on a computer
sc -Create -ServiceName ApolloSvc -DisplayName "Apollo PSExec" -BinPath C:\Users\Public\apollo_service.exe -Computer DC1

# Delete a service
sc -Delete -ServiceName ApolloSvc -Computer DC1
```

## MITRE ATT&CK Mapping

- T1106