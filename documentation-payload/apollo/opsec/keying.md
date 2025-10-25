+++
title = "Environmental Keying"
chapter = false
weight = 103
+++

## Environmental Keying in Apollo

Environmental keying is a technique that restricts agent execution to specific systems. If the keying check fails, the agent will exit immediately and silently without executing any code or attempting to connect to the C2 server.

### Purpose

Environmental keying helps protect against:
- Accidental execution on unintended systems
- Sandbox detonation and automated analysis

### Keying Methods

Apollo supports three methods of environmental keying:

#### 1. Hostname Keying

The agent will only execute if the machine's hostname matches the specified value.

**Use Case:** When you know the exact hostname of your target system.

**Example:** If you set the keying value to `WORKSTATION-01`, the agent will only run on a machine with that exact hostname.

**Security:** Secure (hash-based)

#### 2. Domain Keying

The agent will only execute if the machine's domain name matches the specified value. Domain matching is forgiving and checks both the full domain and individual parts.

**Use Case:** When targeting systems within a specific Active Directory domain.

**Example:** If you set the keying value to `CONTOSO`, the agent will match:
- Full domain: `CONTOSO.LOCAL`
- Full domain: `CORP.CONTOSO.COM`
- Domain part: `CONTOSO` (from `CONTOSO.LOCAL`)
- Domain part: `CONTOSO` (from `CORP.CONTOSO.COM`)

This flexibility handles cases where `Environment.UserDomainName` may return different formats (e.g., `CONTOSO` vs `CONTOSO.LOCAL`).

**Security:** Secure (hash-based)

#### 3. Registry Keying

The agent will only execute if a specific registry value matches or contains the specified value. This method offers two comparison modes:

**Matches Mode (Secure - Recommended):**
- Uses SHA256 hash comparison
- The registry value must exactly match the keying value (case-insensitive)
- Hash stored in binary, not plaintext
- More secure but requires exact match

**Contains Mode (WEAK - Use with Caution):**
- Uses plaintext substring comparison
- The registry value must contain the keying value anywhere within it
- ⚠️ **WARNING:** Stores the keying value in **PLAINTEXT** in the binary
- ⚠️ **WARNING:** Easily extracted with strings command
- More flexible but significantly less secure

**Example Matches Mode:**
```
Registry Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
Registry Value: Windows 10 Pro
Comparison: Matches
```
Agent executes only if the ProductName exactly matches "Windows 10 Pro"

**Example Contains Mode (WEAK):**
```
Registry Path: HKLM\SOFTWARE\Company\Product\InstallID
Registry Value: UniqueInstallGUID-12345
Comparison: Contains
```
Agent executes if InstallID contains "UniqueInstallGUID-12345" anywhere in the value

**Registry Path Format:**
`HIVE\SubKey\Path\To\ValueName`

Supported hives:
- `HKLM` or `HKEY_LOCAL_MACHINE`
- `HKCU` or `HKEY_CURRENT_USER`
- `HKCR` or `HKEY_CLASSES_ROOT`
- `HKU` or `HKEY_USERS`
- `HKCC` or `HKEY_CURRENT_CONFIG`

### Configuration

During the agent build process, you can enable keying through the build parameters:

1. **Enable Keying** - Check this box to enable environmental keying
2. **Keying Method** - Select "Hostname", "Domain", or "Registry"
3. **For Hostname/Domain:**
   - **Keying Value** - Enter the hostname or domain name to match (case-insensitive)
4. **For Registry:**
   - **Registry Path** - Full path including hive, subkey, and value name
   - **Registry Value** - The value to check against
   - **Registry Comparison** - "Matches" (secure, hash-based) or "Contains" (WEAK, plaintext)

### Implementation Details

- **Hash-Based Storage (Hostname/Domain/Registry-Matches):** The keying value is never stored in plaintext in the agent binary. Instead, a SHA256 hash of the uppercase value is embedded
- **Plaintext Storage (Registry-Contains):** ⚠️ When using Registry keying with "Contains" mode, the value is stored in **plaintext** in the binary - easily extractable
- **Uppercase Normalization:** All values (except Registry-Contains mode) are converted to uppercase before hashing to ensure consistent matching regardless of case
- **Runtime Hashing:** During execution, the agent hashes the current hostname/domain/registry-value and compares it to the stored hash
- **Forgiving Domain Matching:** For domain keying, the agent checks:
  1. The full domain name (e.g., `CORP.CONTOSO.LOCAL`)
  2. Each part split by dots (e.g., `CORP`, `CONTOSO`, `LOCAL`)

### Example Scenarios

**Scenario 1: Targeted Workstation**
```
Enable Keying: Yes
Keying Method: Hostname
Keying Value: FINANCE-WS-42
```
This agent will only execute on the machine named `FINANCE-WS-42`.

**Scenario 2: Domain-Wide Campaign**
```
Enable Keying: Yes
Keying Method: Domain
Keying Value: CONTOSO
```
This agent will execute on machines where the domain contains `CONTOSO`:
- Machines in domain `CONTOSO` ✅
- Machines in domain `CONTOSO.LOCAL` ✅
- Machines in domain `CORP.CONTOSO.COM` ✅
- Machines in domain `FABRIKAM.COM` ❌

**Scenario 3: Registry Keying (Matches - Secure)**
```
Enable Keying: Yes
Keying Method: Registry
Registry Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName
Registry Value: Windows 10 Enterprise
Registry Comparison: Matches
```
This agent will only execute on systems running Windows 10 Enterprise (exact match).

**Scenario 4: Registry Keying (Contains - WEAK)**
```
Enable Keying: Yes
Keying Method: Registry
Registry Path: HKLM\SOFTWARE\YourCompany\CustomApp\InstallID
Registry Value: SecretMarker-ABC123
Registry Comparison: Contains
```
This agent will execute on systems where the registry value contains "SecretMarker-ABC123" anywhere.
⚠️ WARNING: "SecretMarker-ABC123" is stored in plaintext in the binary.

**Scenario 5: No Keying (Default)**
```
Enable Keying: No
```
This agent will execute on any system (traditional behavior).

