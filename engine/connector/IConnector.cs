using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;

namespace adeleg.engine.connector
{
    public enum ObjectClass
    {
        UnknownTrustee,
        Container,
        DomainRoot,
        Group,
        User,
        Computer,
    }

    public static class ObjectClassHelper
    {
        public static ObjectClass FromString(string objClass, bool isTrustee)
        {
            objClass = objClass.Trim().ToLowerInvariant();
            if (objClass == "domaindns" || objClass == "configuration")
                return ObjectClass.DomainRoot;
            if (objClass == "computer")
                return ObjectClass.Computer;
            if (objClass == "user")
                return ObjectClass.User;
            if (objClass == "group")
                return ObjectClass.Group;
            if (objClass == "container" || objClass == "organizationalunit" || objClass == "infrastructureupdate" || objClass == "builtindomain")
                return ObjectClass.Container;
            
            if (isTrustee)
                return ObjectClass.UnknownTrustee;
            else
                return ObjectClass.Container;
        }
    }

    public struct ObjectRecord
    {
        public string distinguishedName;
        public string mostSpecificClass;
        public CommonSecurityDescriptor securityDescriptor;
        public bool adminCount;
    }

    public interface IConnector
    {
        string GetRootDomainNC();

        string GetSchemaNC();

        string GetConfigurationNC();

        string[] GetPartitionDNs();

        // Returns the security identifier for the given domain's DN, if it's a domain, or null otherwise (e.g. if it's a schema/config/DNS partition)
        SecurityIdentifier GetDomainSidByPartitionDN(string partitionDN);

        CommonSecurityDescriptor GetAdminSDHolderSDByPartitionDN(string partitionDN);

        Dictionary<Guid, string> GetSchemaClasses();

        Dictionary<Guid, string> GetSchemaAttributes();

        Dictionary<Guid, string> GetControlAccessRights();

        Dictionary<Guid, Tuple<string, HashSet<Guid>>> GetPropertySets();

        Dictionary<string, string> GetDefaultSddlPerClass();
        
        IEnumerable<ObjectRecord> ScanSecurityDescriptors(string baseDN, bool recurse);

        /**
         * Returns a tuple with (ObjectClass, dn, samAccountName) given a SID
         */
        Tuple<ObjectClass, string, string> GetDnAndSamAccountNameBySid(SecurityIdentifier sid);

        SecurityIdentifier GetSidByDn(string principalDN);

        string GetMostSpecificObjectClassByDn(string dn);

        HashSet<string> GetDirectGroupMemberDNs(string groupDN);
    }
}
