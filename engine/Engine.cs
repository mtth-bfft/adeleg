using adeleg.engine.connector;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace adeleg.engine
{
    public struct ForestMetadata {
        public SecurityIdentifier forestSid;
        public SecurityIdentifier schemaAdminSid;
        public string schemaNC;
        public Dictionary<string, SecurityIdentifier> domainSidPerPartition;
        public Dictionary<string, SecurityIdentifier> domainAdminsSidPerPartition;
        public Dictionary<Guid, string> schemaClassNamePerGuid;
        public Dictionary<Guid, string> schemaAttributeNamePerGuid;
        public Dictionary<Guid, string> schemaPropertySetNamePerGuid;
        public Dictionary<Guid, HashSet<Guid>> schemaPropertySetMembersPerGuid;
        public Dictionary<Guid, string> schemaControlAccessNamePerGuid;
        public Dictionary<string, string> defaultSddlPerClassName;
        public Dictionary<string, Dictionary<string, CommonSecurityDescriptor>> defaultSdPerPartitionPerClassName;
        public HashSet<SecurityIdentifier> tier0Sids;
        public Dictionary<string, CommonSecurityDescriptor> adminSdHolderSdPerPartition;
        public HashSet<string> adminSdHolderProtectedDn;
        public Dictionary<string, Dictionary<SecurityIdentifier, Tuple<ObjectClass, string, string>>> sidResolutionCachePerPartition;
    }

    public class Engine
    {
        private readonly static SecurityIdentifier creatorOwnerSid = new SecurityIdentifier("S-1-3-0");
        private readonly static SecurityIdentifier creatorGroupSid = new SecurityIdentifier("S-1-3-1");
        private readonly static SecurityIdentifier everyoneSid = new SecurityIdentifier("S-1-1-0");
        private readonly static SecurityIdentifier administratorsSid = new SecurityIdentifier("S-1-5-32-544");
        private readonly static SecurityIdentifier localSystemSid = new SecurityIdentifier("S-1-5-18");

        /**
         * Group resolution is limited to the same domain: adding users from other domains across trusts
         * won't protect them. These groups are present in both root and non-root domains.
         */
        private readonly static string[] adminSdHolderRecursiveProtectedGroupSidsAllDomains = new string[]
        {
            "S-1-5-32-544", // Administrators
            "S-1-5-32-550", // Print Operators
            "S-1-5-32-551", // Backup Operators
            "S-1-5-32-552", // Replicator
            "S-1-5-32-549", // Server Operators
            "S-1-5-32-548", // Account Operators
            "{domainSid}-512", // Domain Admins
            "{domainSid}-526", // Key Admins
        };
        /**
         * Group resolution is limited to the same domain: adding users from other domains across trusts
         * won't protect them. These groups are present in both root and non-root domains.
         */
        private readonly static string[] adminSdHolderRecursiveProtectedGroupSidsRootDomains = new string[]
        {
            "{domainSid}-518", // Schema Admins
            "{domainSid}-519", // Enterprise Admins
            "{domainSid}-527", // Enterprise Key Admins
        };
        /**
         * Microsoft's documentation (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
         * states that "Domain Controllers" and "Read-Only Domain Controllers" are protected, which (unfortunately) is wrong.
         */
        private readonly static string[] adminSdHolderNonRecursiveProtectedSids = new string[]
        {
            "{domainSid}-502", // krbtgt
            "{domainSid}-516", // Domain Controllers
            "{domainSid}-521", // Read-Only Domain Controllers
        };
        private Dictionary<string, IConnector> dataSourcePerNamingContext = new Dictionary<string, IConnector>();
        private Dictionary<string, string> forestRootPerNamingContext = new Dictionary<string, string>();
        private Dictionary<string, ForestMetadata> metadataPerForest = new Dictionary<string, ForestMetadata>();

        public Engine(IEnumerable<IConnector> dataSources)
        {
            foreach (IConnector dataSource in dataSources)
            {
                foreach (string partitionDN in dataSource.GetPartitionDNs())
                {
                    string forestDN = dataSource.GetRootDomainNC();

                    // If two sources provide the same partition, only one is kept (random)
                    dataSourcePerNamingContext[partitionDN] = dataSource;
                    forestRootPerNamingContext[partitionDN] = forestDN;
                }
            }
            foreach (string forestDN in forestRootPerNamingContext.Values)
            {
                if (!dataSourcePerNamingContext.ContainsKey(forestDN))
                {
                    throw new Exception($"Root domain {forestDN} needs to be included in data inputs to be scanned");
                }
            }

            ScanAllMetadata();
        }

        public HashSet<string> ListPartitionDNs()
        {
            return new HashSet<string>(dataSourcePerNamingContext.Keys);
        }

        private void ScanAllMetadata()
        {
            metadataPerForest.Clear();
            foreach (string forestDN in forestRootPerNamingContext.Values)
            {
                if (!metadataPerForest.ContainsKey(forestDN))
                {
                    metadataPerForest[forestDN] = ScanForestMetadata(forestDN, dataSourcePerNamingContext[forestDN]);
                }
            }

            // Perform recursive operations that can require info from one forest to fill metadata
            // of another (e.g. recursive group memberships)
            foreach (KeyValuePair<string, ForestMetadata> forest in metadataPerForest)
            {
                foreach (SecurityIdentifier sid in forest.Value.tier0Sids.ToArray())
                {
                    Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(forest.Key, sid);
                    if (resolved == null || (resolved.Item2 == null && resolved.Item3 == null))
                    {
                        Console.WriteLine($" [!] Warning: unable to resolve {sid} in {forest.Key}");
                        continue;
                    }

                    if (resolved.Item1 == ObjectClass.Group)
                    {
                        foreach (string memberDN in GetRecursiveGroupMemberDNs(resolved.Item2))
                        {
                            SecurityIdentifier memberSid = ResolveDnToSid(memberDN);
                            if (memberSid == null)
                            {
                                Console.WriteLine($" [!] Warning: unable to resolve {memberDN} to a SID");
                                continue;
                            }

                            forest.Value.tier0Sids.Add(memberSid);
                        }
                    }
                }
            }
        }

        private ForestMetadata ScanForestMetadata(string forestDN, IConnector rootDomainDataSource)
        {
            SecurityIdentifier forestSid = rootDomainDataSource.GetDomainSidByPartitionDN(forestDN);

            ForestMetadata res = new ForestMetadata
            {
                forestSid = forestSid,
                schemaAdminSid = new SecurityIdentifier($"{forestSid}-518"),
                schemaNC = rootDomainDataSource.GetSchemaNC(),

                domainSidPerPartition = new Dictionary<string, SecurityIdentifier>(),
                domainAdminsSidPerPartition = new Dictionary<string, SecurityIdentifier>(),
                sidResolutionCachePerPartition = new Dictionary<string, Dictionary<SecurityIdentifier, Tuple<ObjectClass, string, string>>>(),
                defaultSdPerPartitionPerClassName = new Dictionary<string, Dictionary<string, CommonSecurityDescriptor>>(),
                adminSdHolderSdPerPartition = new Dictionary<string, CommonSecurityDescriptor>(),
                adminSdHolderProtectedDn = new HashSet<string>(),
                tier0Sids = new HashSet<SecurityIdentifier>(),

                // Inventory schema classes so we can display pretty names
                schemaClassNamePerGuid = new Dictionary<Guid, string>(rootDomainDataSource.GetSchemaClasses()),

                // Inventory schema attributes so we can display pretty names
                schemaAttributeNamePerGuid = new Dictionary<Guid, string>(rootDomainDataSource.GetSchemaAttributes()),

                // Inventory property sets so we can know which properties they give access to, and display pretty names
                schemaPropertySetNamePerGuid = new Dictionary<Guid, string>(),
                schemaPropertySetMembersPerGuid = new Dictionary<Guid, HashSet<Guid>>()
            };

            foreach (KeyValuePair<Guid, Tuple<string, HashSet<Guid>>> propset in rootDomainDataSource.GetPropertySets())
            {
                res.schemaPropertySetNamePerGuid[propset.Key] = propset.Value.Item1;
                res.schemaPropertySetMembersPerGuid[propset.Key] = propset.Value.Item2;
            }

            // Inventory control access names so we can display pretty names
            res.schemaControlAccessNamePerGuid = new Dictionary<Guid, string>(rootDomainDataSource.GetControlAccessRights());

            // Inventory default security descriptor as text (SDDL) for each class in this forest
            res.defaultSddlPerClassName = rootDomainDataSource.GetDefaultSddlPerClass();

            // Foreach partition in this forest
            foreach (KeyValuePair<string, string> kv in forestRootPerNamingContext)
            {
                if (kv.Value != forestDN)
                    continue;

                string partitionDN = kv.Key;
                IConnector partitionDataSource = dataSourcePerNamingContext[partitionDN];
                SecurityIdentifier domainSid = partitionDataSource.GetDomainSidByPartitionDN(kv.Key);
                res.sidResolutionCachePerPartition[partitionDN] = new Dictionary<SecurityIdentifier, Tuple<ObjectClass, string, string>>();

                // Compute per-partition default SDs so we can detect that some explicit object ACE are just copies from schema
                res.defaultSdPerPartitionPerClassName[partitionDN] = new Dictionary<string, CommonSecurityDescriptor>();
                foreach (KeyValuePair<string, string> entry in res.defaultSddlPerClassName)
                {
                    res.defaultSdPerPartitionPerClassName[partitionDN].Add(entry.Key, ParseSddl(entry.Value, domainSid, res.forestSid));
                }

                foreach (SecurityIdentifier sid in InventoryBuiltinTier0SidsForPartition(domainSid, res.forestSid))
                {
                    res.tier0Sids.Add(sid);
                }

                if (domainSid != null) // It's a domain partition
                {
                    res.domainSidPerPartition[partitionDN] = domainSid;
                    res.domainAdminsSidPerPartition[partitionDN] = new SecurityIdentifier($"{domainSid}-512");

                    // Store the adminsdholder container's security descriptor: it will be used as a comparison baseline for
                    // protected objects
                    string adminSdHolderDN = GetAdminSdHolderDnForPartition(partitionDN);
                    ObjectRecord adminsdholder = partitionDataSource.ScanSecurityDescriptors(adminSdHolderDN, false).FirstOrDefault();
                    res.adminSdHolderSdPerPartition[partitionDN] = adminsdholder.securityDescriptor;

                    // Fills adminSdHolderProtectedDn so that we can check each object is properly protected
                    // when we see them, and no object is protected but shouldn't be anymore
                    res.adminSdHolderProtectedDn.UnionWith(InventoryAdminSdHolderProtectedDnPerDomain(partitionDN, partitionDataSource, domainSid, res.forestSid));
                }
                else
                {
                    res.domainAdminsSidPerPartition[partitionDN] = new SecurityIdentifier($"{res.forestSid}-512");
                }
            }
            return res;
        }

        /**
         * Returns a tuple with (ObjectClass, dn, samAccountName) given a SID
         */
        private Tuple<ObjectClass, string, string> ResolveFromSid(string partitionDN, SecurityIdentifier sid)
        {
            bool isDomainSid = sid.Value.ToUpperInvariant().StartsWith("S-1-5-21-");
            string forestDN = forestRootPerNamingContext[partitionDN];
            ForestMetadata forestMetadata;
            Tuple<ObjectClass, string, string> res;

            // Some SIDs need to be resolved to a DN in the specified domain (e.g. S-1-5-32-544)
            // Some SIDs (S-1-5-21-xxx) need to be resolved in the forest that contains them, even if they
            // appear in ACLs in various domains
            if (isDomainSid)
            {
                foreach (ForestMetadata otherForestMetadata in this.metadataPerForest.Values)
                {
                    foreach (KeyValuePair<string, SecurityIdentifier> otherSid in otherForestMetadata.domainSidPerPartition)
                    {
                        if (otherSid.Value.IsEqualDomainSid(otherSid.Value))
                        {
                            partitionDN = otherSid.Key;
                            break;
                        }
                    }
                }
            }

            // Metadata might not be available yet, e.g. if we're resolving SIDs during startup
            if (metadataPerForest.TryGetValue(forestDN, out forestMetadata))
            {
                forestMetadata.sidResolutionCachePerPartition[partitionDN].TryGetValue(sid, out res);
                if (res != null)
                {
                    return res;
                }
            }

            res = dataSourcePerNamingContext[partitionDN].GetDnAndSamAccountNameBySid(sid);
            // Try to resolve locally if not already ok
            if ((res == null || (res.Item2 == null && res.Item3 == null)) && !isDomainSid)
            {
                try
                {
                    NTAccount name = (NTAccount)sid.Translate(typeof(NTAccount));
                    res = Tuple.Create<ObjectClass, string, string>(ObjectClass.UnknownTrustee, null, name.ToString());
                }
                catch (IdentityNotMappedException) { }
            }
            if (res == null || (res.Item2 == null && res.Item3 == null))
            {
                res = Tuple.Create<ObjectClass, string, string>(ObjectClass.UnknownTrustee, null, null);
            }
            if (forestMetadata.sidResolutionCachePerPartition != null)
            {
                forestMetadata.sidResolutionCachePerPartition[partitionDN].Add(sid, res);
            }
            return res;
        }

        private SecurityIdentifier ResolveDnToSid(string principalDN)
        {
            Tuple<string, IConnector> kv = GetDataSourceForDN(principalDN);
            if (kv == null)
                return null;
            IConnector dataSource = kv.Item2;
            return dataSource.GetSidByDn(principalDN);
        }

        private static CommonSecurityDescriptor ParseSddl(string sddl, SecurityIdentifier domainSID, SecurityIdentifier rootDomainSID)
        {
            if (domainSID == null)
            {
                domainSID = rootDomainSID;
            }
            string specialized = sddl
                .Replace(
                    ";AO)", // Account Operators
                    ";S-1-5-32-548)"
                ).Replace(
                    ";DA)", // Domain Admins
                    string.Format(";{0}-512)", domainSID)
                ).Replace(
                    ";DU)", // Domain Users
                    string.Format(";{0}-513)", domainSID)
                ).Replace(
                    ";DG)", // Domain Guests
                    string.Format(";{0}-514)", domainSID)
                ).Replace(
                    ";DC)", // Domain Computers
                    string.Format(";{0}-515)", domainSID)
                ).Replace(
                    ";DD)", // Domain Controllers
                    string.Format(";{0}-516)", domainSID)
                ).Replace(
                    ";CA)", // Certificate Publishers
                    string.Format(";{0}-517)", domainSID)
                ).Replace(
                    ";RS)", // RAS and IAS Servers
                    string.Format(";{0}-553)", domainSID)
                ).Replace(
                    ";PA)", // Group Policy Admins / Creator Owner
                    string.Format(";{0}-520)", domainSID)
                ).Replace(
                    ";RO)", // Enterprise Read-only Domain Controllers
                    string.Format(";{0}-498)", rootDomainSID)
                ).Replace(
                    ";SA)", // Schema Admins
                    string.Format(";{0}-518)", rootDomainSID)
                ).Replace( //  Enterprise Admins
                    ";EA)",
                    string.Format(";{0}-519)", rootDomainSID)
                );
            return new CommonSecurityDescriptor(true, true, specialized);
        }

        private Tuple<string, IConnector> GetDataSourceForDN(string dn)
        {
            int longestMatch = 0;
            Tuple<string, IConnector> res = null;
            foreach (KeyValuePair<string, IConnector> kv in this.dataSourcePerNamingContext)
            {
                if (dn.EndsWith(kv.Key) && kv.Key.Length > longestMatch)
                {
                    res = Tuple.Create(kv.Key, kv.Value);
                    longestMatch = kv.Key.Length;
                }
            }
            return res;
        }

        private HashSet<string> GetRecursiveGroupMemberDNs(string groupDN)
        {
            Tuple<string, IConnector> dataSource = GetDataSourceForDN(groupDN);
            HashSet<string> members = dataSource.Item2.GetDirectGroupMemberDNs(groupDN);

            foreach (string member in members)
            {
                Tuple<string, IConnector> dataSourceMember = GetDataSourceForDN(member);
                if (dataSourceMember == null)
                    continue;
                string objClass = dataSourceMember.Item2.GetMostSpecificObjectClassByDn(member);
                if (objClass != "group")
                    continue;
                members.UnionWith(GetRecursiveGroupMemberDNs(member));
            }

            return members;
        }

        private HashSet<string> GetRecursiveGroupMemberDNs(string partitionDN, SecurityIdentifier groupSid)
        {
            Tuple<ObjectClass, string, string> res = dataSourcePerNamingContext[partitionDN].GetDnAndSamAccountNameBySid(groupSid);
            return GetRecursiveGroupMemberDNs(res.Item2);
        }

        /**
         * Pre-compute an inventory of objects supposed to be protected, so we can later check whether they are
         * actually properly protected. This influences the looks of the DACL of these objects, and depends
         * on groups elsewhere, so this needs to be pre-computed before scanning partitions.
         */
        private HashSet<string> InventoryAdminSdHolderProtectedDnPerDomain(string partitionDN, IConnector dataSource, SecurityIdentifier domainSid, SecurityIdentifier rootDomainSid)
        {
            HashSet<string> res = new HashSet<string>();
            List<string> sidTemplates = new List<string>();
            sidTemplates.AddRange(adminSdHolderRecursiveProtectedGroupSidsAllDomains);
            if (partitionDN == dataSource.GetRootDomainNC())
            {
                sidTemplates.AddRange(adminSdHolderRecursiveProtectedGroupSidsRootDomains);
            }

            foreach (string sidTemplate in sidTemplates)
            {
                SecurityIdentifier sid = new SecurityIdentifier(sidTemplate.Replace("{domainSid}", domainSid.ToString()).Replace("{rootDomainSid}", rootDomainSid.ToString()));
                
                Tuple<ObjectClass, string, string> dn = dataSource.GetDnAndSamAccountNameBySid(sid);
                res.Add(dn.Item2.ToLower());

                foreach (string memberDN in GetRecursiveGroupMemberDNs(partitionDN, sid))
                {
                    res.Add(memberDN.ToLower());
                }
            }
            foreach (string sidTemplate in adminSdHolderNonRecursiveProtectedSids)
            {
                SecurityIdentifier sid = new SecurityIdentifier(sidTemplate.Replace("{domainSid}", domainSid.ToString()).Replace("{rootDomainSid}", rootDomainSid.ToString()));

                Tuple<ObjectClass, string, string> dn = dataSource.GetDnAndSamAccountNameBySid(sid);
                res.Add(dn.Item2.ToLower());
            }
            return res;
        }

        private HashSet<SecurityIdentifier> InventoryBuiltinTier0SidsForPartition(SecurityIdentifier domainSid, SecurityIdentifier rootDomainSid)
        {
            HashSet<SecurityIdentifier> res = new HashSet<SecurityIdentifier>();
            if (domainSid == null)
                domainSid = rootDomainSid;

            // Local System
            res.Add(new SecurityIdentifier("S-1-5-18"));

            // Local Service
            res.Add(new SecurityIdentifier("S-1-5-19"));

            // Network Service
            res.Add(new SecurityIdentifier("S-1-5-20"));

            // Enterprise Domain Controllers
            res.Add(new SecurityIdentifier("S-1-5-9"));

            // Administrators
            res.Add(new SecurityIdentifier("S-1-5-32-544"));

            // Print Operators
            res.Add(new SecurityIdentifier("S-1-5-32-550"));

            // Backup Operators
            res.Add(new SecurityIdentifier("S-1-5-32-551"));

            // Replicator
            res.Add(new SecurityIdentifier("S-1-5-32-552"));

            // Domain Controllers
            res.Add(new SecurityIdentifier($"{domainSid}-516"));

            // Schema Admins
            res.Add(new SecurityIdentifier($"{rootDomainSid}-518"));

            // Enterprise Admins
            res.Add(new SecurityIdentifier($"{rootDomainSid}-519"));

            // Domain Admins
            if (domainSid != null)
                res.Add(new SecurityIdentifier($"{domainSid}-512"));

            // Server Operators
            res.Add(new SecurityIdentifier("S-1-5-32-549"));

            // Account Operators
            res.Add(new SecurityIdentifier("S-1-5-32-548"));

            // Enterprise Key Admins
            if (domainSid != null)
                res.Add(new SecurityIdentifier($"{rootDomainSid}-527"));

            // Key Admins
            if (domainSid != null)
                res.Add(new SecurityIdentifier($"{domainSid}-526"));

            // Krbtgt
            if (domainSid != null)
                res.Add(new SecurityIdentifier($"{domainSid}-502"));

            return res;
        }

        private static bool IsAceIncludedInAcl(QualifiedAce ace, DiscretionaryAcl referenceAcl)
        {
            foreach (GenericAce referenceGenericAce in referenceAcl)
            {
                QualifiedAce referenceAce = (QualifiedAce)referenceGenericAce;

                // Inheritance flags are not applied by AD here, just copied as-is from defaultSecurityDescriptor
                if (referenceAce.AceType != ace.AceType ||
                    (referenceAce.AccessMask & ace.AccessMask) != ace.AccessMask ||
                    referenceAce.InheritanceFlags != ace.InheritanceFlags ||
                    referenceAce.PropagationFlags != ace.PropagationFlags ||
                    referenceAce.SecurityIdentifier != ace.SecurityIdentifier)
                {
                    continue;
                }

                if (referenceAce.AceType == AceType.AccessAllowedObject)
                {
                    ObjectAce objAce = (ObjectAce)ace;
                    ObjectAce defaultObjAce = (ObjectAce)referenceAce;

                    if (objAce.ObjectAceFlags != defaultObjAce.ObjectAceFlags)
                    {
                        continue;
                    }
                    if ((objAce.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0 &&
                        objAce.ObjectAceType != defaultObjAce.ObjectAceType)
                    {
                        continue;
                    }
                    if ((objAce.ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0 &&
                        objAce.InheritedObjectAceType != defaultObjAce.InheritedObjectAceType)
                    {
                        continue;
                    }
                }

                return true;
            }
            return false;
        }

        private List<Result> CheckAdminSdHolderAcl(CommonSecurityDescriptor sd, SecurityIdentifier domainSid, string dn, string partitionDN)
        {
            List<Result> res = new List<Result>();
            //if ((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
            //{
            //    res.Add(new Result(ResultClass.Warning, dn, ObjectClass.Container, null, ObjectClass.UnknownTrustee, $"DACL should have inheritance blocked"));
            //}
            //else if (sd.Owner != administratorsSid && sd.Owner != new SecurityIdentifier($"{domainSid}-512"))
            //{
            //    Tuple<ObjectClass, string> resolved = this.ResolveSidToDn(partitionDN, sd.Owner);
            //    res.Add(new Result(ResultClass.Error, dn, ObjectClass.Container, resolved.Item2, resolved.Item1, $"owner should be the Domain Admins group"));
            //}
            //else
            //{
            //    foreach (QualifiedAce ace in sd.DiscretionaryAcl)
            //    {
            //        // TODO: check based on hardcoded baseline list
            //    }
            //}
            return res;
        }

        private static string GetAdminSdHolderDnForPartition(string partitionDN)
        {
            return $"CN=AdminSDHolder,CN=System,{partitionDN}";
        }

        /**
         * Scan logic, called initially on the root of all partitions, and can be called via the GUI on
         * susbtrees (e.g. when using F5 in per-resource view with a container selected), or on individual
         * objects (e.g. when using F5 in per-trustee view, to start by immediately re-scanning objects where
         * we knew there were delegations, before re-scanning the root of partitions to have a complete view)
         */
        public List<Result> Scan(string baseDN, bool recurse)
        {
            List<Result> res = new List<Result>();
            Tuple<string, IConnector> tup = GetDataSourceForDN(baseDN);
            string partitionDN = tup.Item1;
            IConnector dataSource = tup.Item2;
            string forestDN = forestRootPerNamingContext[partitionDN];
            ForestMetadata forestMetadata = metadataPerForest[forestDN];
            CommonSecurityDescriptor adminSdHolderSd;
            Dictionary<string, CommonSecurityDescriptor> defaultSdPerClass = forestMetadata.defaultSdPerPartitionPerClassName[partitionDN];
            SecurityIdentifier domainAdminsSid = forestMetadata.domainAdminsSidPerPartition[partitionDN];
            forestMetadata.adminSdHolderSdPerPartition.TryGetValue(partitionDN, out adminSdHolderSd);

            foreach (ObjectRecord obj in dataSource.ScanSecurityDescriptors(baseDN, recurse))
            {
                // TODO: add a post-processing phase, based on a list of DNs that we scanned and had DACL inheritance blocked,
                // to add the info in each delegation of the list of any child DN that has inheritance blocked as "exceptions"

                // For AdminSDHolder-protected objects, enforce that DACL inheritance is blocked and
                // ACEs are restricted enough
                if (forestMetadata.adminSdHolderProtectedDn.Contains(obj.distinguishedName.ToLower())) // object is supposed to be as protected as the AdminSDHolder
                {
                    // Owner is supposed to be Domain Admins, copied from AdminSdHolder
                    if (obj.securityDescriptor.Owner != null && obj.securityDescriptor.Owner != domainAdminsSid)
                    {
                        Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(partitionDN, obj.securityDescriptor.Owner);
                        List<string> errors = new List<string>();

                        if (adminSdHolderSd != null && adminSdHolderSd.Owner != null && adminSdHolderSd.Owner != domainAdminsSid)
                        {
                            errors.Add("Owner is copied from CN=AdminSDHolder,CN=System but that container's owner has been changed from the default (Domain Admins)");
                        }
                        else
                        {
                            errors.Add("Owner should be Domain Admins, copied from CN=AdminSdHolder,CN=System");
                        }

                        res.Add(new OwnerResult(
                            new ResultLocationDn(obj.distinguishedName, obj.mostSpecificClass),
                            new ResultTrustee(obj.securityDescriptor.Owner, resolved.Item1, resolved.Item2, resolved.Item3, forestMetadata.tier0Sids.Contains(obj.securityDescriptor.Owner)),
                            new string[] { },
                            errors
                        ));
                    }

                    if (adminSdHolderSd != null)
                    {
                        // DACL is supposed to be 100% the same as adminSDHolder's one
                        foreach (QualifiedAce resAce in obj.securityDescriptor.DiscretionaryAcl)
                        {
                            Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(partitionDN, resAce.SecurityIdentifier);
                            List<string> warnings = new List<string>();
                            List<string> errors = new List<string>();

                            if ((resAce.AceFlags & AceFlags.Inherited) != 0 &&
                                (adminSdHolderSd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
                            {
                                errors.Add("This object is protected by the AdminSDHolder mechanism, but AdminSDHolder security descriptor has been modified to allow ACE inheritance, which is a huge security risk");
                            }
                            if (IsAceIncludedInAcl(resAce, adminSdHolderSd.DiscretionaryAcl))
                            {
                                continue; // show it only on the AdminSDHolder object itself, if it's not built-in
                            }
                            errors.Add("Should have been removed by AdminSDHolder mechanism, check that the domain controller with Primary Domain Controller Emulator role is running, replication is working, and AdminSDHolder has its default DACL");

                            res.Add(new AceAddResult(
                                resAce,
                                forestMetadata,
                                new ResultLocationDn(obj.distinguishedName, obj.mostSpecificClass),
                                new ResultTrustee(resAce.SecurityIdentifier, resolved.Item1, resolved.Item2, resolved.Item3, forestMetadata.tier0Sids.Contains(resAce.SecurityIdentifier)),
                                warnings,
                                errors
                            ));
                        }
                    }
                    continue;
                }

                if (partitionDN.ToLowerInvariant() == forestMetadata.schemaNC.ToLowerInvariant() &&
                    obj.securityDescriptor.Owner != null &&
                    obj.securityDescriptor.Owner != forestMetadata.schemaAdminSid)
                {
                    Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(partitionDN, obj.securityDescriptor.Owner);
                    List<string> warnings = new List<string> { "Schema definition objects should be owned by Schema Admins" };

                    res.Add(new OwnerResult(
                        new ResultLocationDn(obj.distinguishedName, obj.mostSpecificClass),
                        new ResultTrustee(obj.securityDescriptor.Owner, resolved.Item1, resolved.Item2, resolved.Item3, forestMetadata.tier0Sids.Contains(obj.securityDescriptor.Owner)),
                        warnings,
                        new string[] { }
                    ));
                }
                else if (obj.securityDescriptor.Owner != null &&
                    obj.securityDescriptor.Owner != domainAdminsSid &&
                    obj.securityDescriptor.Owner != administratorsSid &&
                    obj.securityDescriptor.Owner != localSystemSid)
                {
                    // TODO: only flag if not within a parent resource's CREATE_CHILD delegation. Requires adding a post-processing phase, to have that info at hand.
                    Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(partitionDN, obj.securityDescriptor.Owner);
                    List<string> warnings = new List<string> { "Should be owned by the Domain Admins or Administrators group" };

                    res.Add(new OwnerResult(
                        new ResultLocationDn(obj.distinguishedName, obj.mostSpecificClass),
                        new ResultTrustee(obj.securityDescriptor.Owner, resolved.Item1, resolved.Item2, resolved.Item3, forestMetadata.tier0Sids.Contains(obj.securityDescriptor.Owner)),
                        warnings,
                        new string[] { }
                    ));
                }

                CommonSecurityDescriptor defaultSD = defaultSdPerClass[obj.mostSpecificClass];

                // TODO: enforce ordering of ACEs: schema/inherited, and deny/allow categories too
                foreach (QualifiedAce objAce in obj.securityDescriptor.DiscretionaryAcl)
                {
                    if (objAce.IsInherited)
                    {
                        continue; // we'll only print the ACE in this object's parent that generated this ACE
                    }
                    if (objAce.AceType != AceType.AccessAllowed && objAce.AceType != AceType.AccessAllowedObject)
                    {
                        continue; // we are only interested in delegations, not rights restrictions
                    }
                    if (IsAceIncludedInAcl(objAce, defaultSD.DiscretionaryAcl))
                    {
                        continue; // if it comes from that class' defaultSecurityDescriptor, flag it in the Schema once, not here
                    }
                    if (objAce.SecurityIdentifier == creatorOwnerSid || objAce.SecurityIdentifier == creatorGroupSid)
                    {
                        continue; // treated in each CreateChild ACE (if any)
                    }
                    // TODO: ignore Owner Rights here, and include it in the description of Create/Delete delegations when present
                    // TODO: ignore SELF here, and include it in description of other delegations?

                    // Hardcoded exceptions, based on reverse engineering, for cases where adding the ACE to a "default ACEs" list
                    // won't generalize on other forests
                    if (objAce.SecurityIdentifier == everyoneSid &&
                        obj.mostSpecificClass == "foreignSecurityPrincipal" &&
                        (objAce.AccessMask & (int)(ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListObject)) == objAce.AccessMask)
                    {
                        continue;
                    }
                    if (objAce.SecurityIdentifier == everyoneSid &&
                        obj.distinguishedName.EndsWith(",CN=Operations,CN=ForestUpdates," + dataSource.GetConfigurationNC()) &&
                        (objAce.AccessMask & (int)(ActiveDirectoryRights.ReadControl | ActiveDirectoryRights.ListChildren | ActiveDirectoryRights.ReadProperty | ActiveDirectoryRights.ListObject)) == objAce.AccessMask)
                    {
                        continue;
                    }

                    Guid objType = Guid.Empty;
                    Guid inheritObjType = Guid.Empty;
                    if (objAce.AceType == AceType.AccessAllowedObject)
                    {
                        ObjectAce objAce2 = (ObjectAce)objAce;
                        objType = objAce2.ObjectAceType;
                        inheritObjType = objAce2.InheritedObjectAceType;
                    }

                    Tuple<ObjectClass, string, string> resolved = this.ResolveFromSid(partitionDN, objAce.SecurityIdentifier);
                    List<string> warnings = new List<string>();
                    List<string> accessRightsDescr = new List<string>();

                    if ((obj.securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 &&
                        obj.adminCount)
                    {
                        string rsrcType = resolved.Item1 == ObjectClass.Group ? "group" : "account";
                        warnings.Add($"Resource {rsrcType} improperly de-privileged after being equivalent to Domain Admin, instead of being decommissionned");
                    }

                    res.Add(new AceAddResult(
                        objAce,
                        forestMetadata,
                        new ResultLocationDn(obj.distinguishedName, obj.mostSpecificClass),
                        new ResultTrustee(objAce.SecurityIdentifier, resolved.Item1, resolved.Item2, resolved.Item3, forestMetadata.tier0Sids.Contains(objAce.SecurityIdentifier)),
                        warnings,
                        new string[] { }
                    ));
                }
            }

            return res;
        }

        /**
         * Generalization of results (going from location DN == CN=Builtin,DC=a,DC=com to
         * location domainRelativeDN CN=Builtin, or going from trustee SID=S-1-5-21-xxx-512 to
         * trustee domainRID=512) can only be done here, not as a method on invidual results:
         * it needs to take into account "do we have a result that matches this one in other
         * partitions?" (if so, do generalize it, otherwise it must remain specific)
         */
        public List<Result> Generalize(List<Result> results)
        {
            List<Result> generalized = new List<Result>();

            for (int i = 0; i < results.Count; i++) {
                Result res = results[i];
                ResultTrustee generalizedTrustee = this.Generalize(res.Trustee);
                ResultLocation generalizedLocation = this.Generalize(res.Location);

                if (res is OwnerResult)
                {
                    generalized.Add(new OwnerResult(
                        res.Location,
                        generalizedTrustee,
                        new string[] { },
                        new string[] { }
                    ));
                }
                else if (res is AceAddResult)
                {
                    AceAddResult res2 = (AceAddResult)res;
                    generalized.Add(new AceAddResult(
                        res2.Ace,
                        res2.GetAccessDescriptionLines(),
                        res.Location,
                        generalizedTrustee,
                        new string[] { },
                        new string[] { }
                    ));
                }
                else if (res is AceRemoveResult res2)
                {
                    generalized.Add(new AceRemoveResult(
                        res2.Ace,
                        res2.GetAccessDescriptionLines(),
                        res.Location,
                        generalizedTrustee,
                        new string[] { },
                        new string[] { }
                    ));
                }
                else
                {
                    throw new Exception($"Unable to generalize result type {res.GetType()}");
                }
            }

            /*
                Result res = results[i];

                ResultLocation newLocation = null;
                if (res.location is ResultLocationDn)
                {
                    ResultLocationDn resDn = (ResultLocationDn)res.location;
                }
                else if (res.location is ResultLocationSchemaDefaultSd)
                {
                    ResultLocationSchemaDefaultSd resSchema = (ResultLocationSchemaDefaultSd)res.location;
                    newLocation = new ResultLocationSchemaDefaultSd(resSchema);
                }
                else
                {
                    throw new Exception($"Generalization of {res.location.GetType()} not supported yet");
                }

                ResultTrustee newTrustee;
                newTrustee = res.trustee;

                Result newResult = null;
                if (res is OwnerResult)
                {
                    newResult = new OwnerResult(newLocation, newTrustee, new string[] { }, new string[] { });
                }
                else if (res is AceAddResult)
                {
                    AceAddResult resAce = (AceAddResult)res;
                    newResult = new AceAddResult(newTrustee, new string[] { }, new string[] { });
                }
                else
                {
                    throw new Exception($"Generalization of {res.GetType()} not supported yet");
                }

                string sidLower = sid.ToString().ToLowerInvariant();
                int lastDash = sidLower.LastIndexOf('-');
                SecurityIdentifier domainSid = new SecurityIdentifier(sidLower.Substring(0, lastDash));
                if (domainSid == forestMetadata.)

                int domainRid = 0;
                int rootDomainRid = 0;

                int rid = int.Parse(objAce.SecurityIdentifier.ToString().Split('-').Last());
                if (partitionDN == forestDN)
                    rootDomainRid = rid;
                else
                    domainRid = rid;
            }

            string domainRelativeDN = null;
            string rootdomainRelativeDN = null;
            if (generalize && dn != null && dn.ToLower().EndsWith("," + domainPartitionDN.ToLower()))
            {
                domainRelativeDN = dn.Substring(0, dn.Length - domainPartitionDN.Length - 1);
                dn = null;
            }
            else if (generalize && dn != null && dn.ToLower().EndsWith("," + rootDomainRelativeDN.ToLower()))
            {
                rootdomainRelativeDN = dn.Substring(0, dn.Length - rootDomainRelativeDN.Length - 1);
                dn = null;
            }*/

            return generalized;
        }

        public ResultTrustee Generalize(ResultTrustee trustee)
        {
            bool isSidGeneralizable = true;

            string strSid = trustee.Sid.ToString().ToUpperInvariant();
            if (strSid.StartsWith("S-1-5-21-"))
            {
                string strRid = strSid.Split('-').Last();
                int rid = int.Parse(strRid);
                if (rid >= 1000)
                {
                    isSidGeneralizable = false;
                }
            }

            if (isSidGeneralizable)
            {
                return new ResultTrustee(trustee.Sid, trustee.Type);
            }
            else if (trustee.SamAccountName != null)
            {
                return new ResultTrustee(null, trustee.Type, null, trustee.SamAccountName);
            }
            else
            {
                return new ResultTrustee(trustee.Sid, trustee.Type, trustee.Dn);
            }
        }

        public ResultLocation Generalize(ResultLocation location)
        {
            if (location is ResultLocationSchemaDefaultSd schema)
            {
                return location;
            }
            // TODO: generalization based on DN: in domain's NC, root domain's NC, configuration NC, etc.
            else
            {
                return location;
            }
        }
    }
}