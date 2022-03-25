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
- `-Modify`

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

### Modify

![delete](../images/sc_modify.png)

#### ServiceName

The name of the service to modify.

#### Computer (optional)

The computer to modify the specified `ServiceName` service.

#### BinPath (optional)

Path to service executable.

#### DisplayName (optional)

The display name of the service to query.

#### Description (optional) 
Set the service description.

#### StartType (optional)
Set the user the service will run as. Defaults to SERVICE_NO_CHANGE.

Valid options: SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_SYSTEM_START

#### Dependencies (optional) 
Set the dependencies for a service. Values can be a comma separated list or an empty string ("") to remove dependencies.

#### ServiceType (optional)
Set the service type.

Valid Options: SERVICE_NO_CHANGE, SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS, SERVICE_INTERACTIVE_PROCESS, SERVICETYPE_NO_CHANGE, SERVICE_WIN32

#### RunAs (optional)

Set the user the service will run as.

#### Password (optional)
Set the service account password.


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