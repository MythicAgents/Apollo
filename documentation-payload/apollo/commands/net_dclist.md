+++
title = "net_dclist"
chapter = false
weight = 103
hidden = false
+++

## Summary
Enumerates domain controllers from the current or specified domain using `DomainController.FindAll()`. Retrieves detailed information including IP addresses, OS versions, and Global Catalog status.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @djhohnstein

### Arguments
- **domain** (Optional String) - Target domain name (defaults to current domain)

## Usage
```
net_dclist
net_dclist lab.local
```

**Raw Output:**
```json
[
  {
    "computer_name": "DC01.lab.local",
    "ip_address": "192.168.1.10",
    "domain": "lab.local",
    "forest": "lab.local",
    "os_version": "Windows Server 2019",
    "global_catalog": true
  }
]
```

**Formatted Output:**
![net_dclist](../images/net_dclist.png)


## Detailed Summary

### Agent Execution Flow

#### 1. Directory Context Creation
```csharp
DirectoryContext ctx;
if (string.IsNullOrEmpty(_data.Parameters))
    ctx = new DirectoryContext(DirectoryContextType.Domain);
else
    ctx = new DirectoryContext(DirectoryContextType.Domain, _data.Parameters.Trim());
```
- Creates `DirectoryContext` for domain controller enumeration
- Uses current domain context if no domain specified
- Targets specific domain if parameter provided

#### 2. Domain Controller Discovery
```csharp
DomainControllerCollection dcCollection;
dcCollection = DomainController.FindAll(ctx);
```
- Uses `DomainController.FindAll()` to discover all domain controllers
- Returns collection of domain controller objects
- Queries Active Directory for controller information

#### 3. Domain Controller Information Extraction
```csharp
foreach (DomainController dc in dcCollection)
{
    var result = new NetDomainController();
    result.ComputerName = dc.Name;
    result.Domain = dc.Domain.ToString();
    result.Forest = dc.Forest.ToString();
    result.OSVersion = dc.OSVersion;
    result.IsGlobalCatalog = dc.IsGlobalCatalog();
}
```
- Iterates through each discovered domain controller
- Extracts computer name, domain, forest, and OS information
- Determines Global Catalog server status

#### 4. IP Address Resolution
```csharp
try
{
    var ips = Dns.GetHostAddresses(result.ComputerName);
    string ipList = "";
    for (int i = 0; i < ips.Length; i++)
    {
        if (i == ips.Length - 1)
            ipList += $"{ips[i].ToString()}";
        else
            ipList += $"{ips[i].ToString()}, ";
    }
    result.IPAddress = ipList;
}
catch (Exception ex)
{
    result.IPAddress = dc.IPAddress;
}
```
- Attempts DNS resolution for each domain controller
- Concatenates multiple IP addresses with comma separation
- Falls back to `dc.IPAddress` if DNS resolution fails
- Handles cases where domain controllers have multiple IPs

#### 5. Response Serialization
```csharp
resp = CreateTaskResponse(_jsonSerializer.Serialize(results.ToArray()), true);
```
- Serializes domain controller array to JSON
- Returns structured data for browser interface processing

### Data Structures

#### NetDomainController
```csharp
struct NetDomainController
{
    public string ComputerName;     // DC hostname/FQDN
    public string IPAddress;        // Comma-separated IP addresses
    public string Domain;           // Domain name
    public string Forest;           // Forest name
    public string OSVersion;        // Operating system version
    public bool IsGlobalCatalog;    // Global Catalog server flag
}
```

### Browser Interface Integration
The JavaScript processes the JSON response into an interactive table with:
- **Shares Button**: Launches `net_shares` command for each DC
- **Copy Icons**: Allows copying computer names and IP addresses
- **Global Catalog Indicator**: Database icon for Global Catalog servers
- **Sortable Columns**: Name, domain, forest, IP, and OS version

### Domain Controller Properties
- **Computer Name**: Fully qualified domain name of the DC
- **IP Address**: All network interfaces (IPv4/IPv6)
- **Domain**: The domain the DC serves
- **Forest**: The forest the domain belongs to
- **OS Version**: Windows Server version and build
- **Global Catalog**: Whether DC hosts Global Catalog database

### Active Directory Integration
Uses .NET Framework's `System.DirectoryServices.ActiveDirectory` namespace:
- **DirectoryContext**: Establishes connection context
- **DomainController.FindAll()**: Discovers all domain controllers
- **DomainController Properties**: Accesses DC metadata
- **DNS Resolution**: Resolves hostnames to IP addresses

## APIs Used
| API | Purpose | Namespace |
|-----|---------|-----------|
| `DirectoryContext` constructor | Create AD connection context | System.DirectoryServices.ActiveDirectory |
| `DomainController.FindAll()` | Discover domain controllers | System.DirectoryServices.ActiveDirectory |
| `DomainController.IsGlobalCatalog()` | Check Global Catalog status | System.DirectoryServices.ActiveDirectory |
| `Dns.GetHostAddresses()` | Resolve hostname to IPs | System.Net |

## MITRE ATT&CK Mapping
- **T1590** - Gather Victim Network Information
  - **T1590.002** - DNS

## Security Considerations
- **Information Disclosure**: Reveals critical AD infrastructure details
- **Network Reconnaissance**: Provides IP addresses and hostnames
- **Attack Planning**: Enables targeting of high-value domain controllers
- **Detection Vectors**: AD queries may be logged and monitored

## Limitations
1. Requires domain-joined context or valid credentials
2. May fail if current user lacks domain query permissions
3. DNS resolution dependent on network connectivity
4. Cross-domain queries may require trust relationships
5. Some DC properties may be restricted based on permissions

## Error Conditions
- **Access Denied**: Insufficient permissions to query domain
- **Domain Not Found**: Specified domain doesn't exist or isn't reachable
- **Network Unreachable**: Cannot connect to domain controllers
- **DNS Resolution Failure**: Cannot resolve DC hostnames to IPs
- **Trust Relationship**: Cross-domain queries fail due to trust issues