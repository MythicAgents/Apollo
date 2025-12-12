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
        }

        public ldap_query(IAgent agent, ApolloInterop.Structs.MythicStructs.MythicTask data) : base(agent, data)
        {
        }

        string[] groupClasses = { "group", "domain", "organizationalUnit", "container" };
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
            string ldapBase = parameters.Base;
            ActiveDirectoryLdapQuery query;
            if (ldapBase != "")
            {
                query = new ActiveDirectoryLdapQuery($"LDAP://{parameters.Base}");
            } else
            {
                Domain domain = Domain.GetCurrentDomain();
                DirectoryEntry ent = domain.GetDirectoryEntry();
                string path = ent.Path;
                string[] pathPieces = ent.Path.Split('/');
                query = new ActiveDirectoryLdapQuery($"LDAP://{pathPieces[pathPieces.Length - 1]}");
                customBrowser.Host = pathPieces[pathPieces.Length - 1];
            }

            List<Dictionary<string, object>> results = new List<Dictionary<string, object>>();
            string filter = parameters.query;
            if(filter == "")
            {
                filter = "(&(objectclass=top)(objectclass=container))";
            }
            try
            {
                results = query.Query(
                    filter: filter,
                    attributesToReturn: parameters.attributes,
                    limit: parameters.limit
                );
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
                    string dnString = dn.ToString();
                    dnString = dnString.Replace("LDAP://", "");
                    customBrowserEntry.DispalyPath = dnString;
                    string[] dnStringPieces = dnString.Split(',');
                    customBrowserEntry.Name = dnStringPieces[0];
                    dnStringPieces = dnStringPieces.Skip(1).Take(dnStringPieces.Length-1).Reverse().ToArray();
                    customBrowserEntry.ParentPath = string.Join(",", dnStringPieces);
                    customBrowserEntry.Metadata = user;
                    if(user.TryGetValue("objectclass", out object oc))
                    {
                        List<string> classes = (List<string>)oc;

                        if (classes.Intersect(groupClasses).Count() > 0)
                        {
                            customBrowserEntry.CanHaveChildren = true;
                        }

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