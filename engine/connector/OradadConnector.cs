using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;

namespace adeleg.engine.connector
{
    internal class OradadConnector : IConnector
    {
        private string rootDir;

        public OradadConnector(string rootDir)
        {
            this.rootDir = rootDir;
        }

        public string GetConfigurationNC()
        {
            throw new NotImplementedException();
        }

        public string GetSchemaNC()
        {
            throw new NotImplementedException();
        }

        public Dictionary<string, string> GetDefaultSddlPerClass()
        {
            throw new NotImplementedException();
        }

        public HashSet<string> GetDirectGroupMemberDNs(string groupDN)
        {
            throw new NotImplementedException();
        }

        public Tuple<ObjectClass, string, string> GetDnAndSamAccountNameBySid(SecurityIdentifier sid)
        {
            throw new NotImplementedException();
        }

        public List<string> GetGroupMemberDNsBySid(string partitionDN, SecurityIdentifier groupSid)
        {
            throw new NotImplementedException();
        }

        public string GetMostSpecificObjectClassByDn(string dn)
        {
            throw new NotImplementedException();
        }

        public Dictionary<Guid, string> GetSchemaClasses()
        {
            throw new NotImplementedException();
        }

        public IEnumerable<ObjectRecord> ScanSecurityDescriptors(string baseDN, bool recurse)
        {
            throw new NotImplementedException();
        }

        CommonSecurityDescriptor IConnector.GetAdminSDHolderSDByPartitionDN(string partitionDN)
        {
            throw new NotImplementedException();
        }

        SecurityIdentifier IConnector.GetDomainSidByPartitionDN(string partitionDN)
        {
            throw new NotImplementedException();
        }

        string[] IConnector.GetPartitionDNs()
        {
            throw new NotImplementedException();
        }

        string IConnector.GetRootDomainNC()
        {
            throw new NotImplementedException();
        }

        public Dictionary<Guid, string> GetSchemaAttributes()
        {
            throw new NotImplementedException();
        }

        public Dictionary<Guid, Tuple<string, HashSet<Guid>>> GetPropertySets()
        {
            throw new NotImplementedException();
        }

        public SecurityIdentifier GetSidByDn(string principalDN)
        {
            throw new NotImplementedException();
        }

        public Dictionary<Guid, string> GetControlAccessRights()
        {
            throw new NotImplementedException();
        }
    }
}
