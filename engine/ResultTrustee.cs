using adeleg.engine.connector;
using System;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace adeleg.engine
{
    public class ResultTrustee
    {
        private ObjectClass _type;
        private string _dn;
        private bool _isTier0;
        private SecurityIdentifier _sid;
        private int _domainRid;
        private int _rootDomainRid;
        private string _samAccountName;

        public ObjectClass Type { get => _type; }
        public string Dn { get => _dn; }
        public string SamAccountName { get => _samAccountName; }
        public SecurityIdentifier Sid { get => _sid; }
        public bool IsTier0 { get => _isTier0; }
        public int DomainRid { get => _domainRid; }
        public int RootDomainRid { get => _rootDomainRid; }

        /**
         * When building a trustee from a live/dumped LDAP security descriptor, you will always have
         * its SID (and, often, its type+DN+samaccountname and whether it should be considered Tier0).
         * SID is used for access right computations, and the rest is just for pretty pretting.
         * When building a trustee for generalized results, we often won't include the SID if it's
         * a S-1-5-21-something-domain-specific which does not generalize at all.
         */
        public ResultTrustee(SecurityIdentifier sid = null, ObjectClass type = ObjectClass.UnknownTrustee, string dn = null, string samAccountName = null, bool isTier0 = false)
        {
            if (sid == null && dn == null && samAccountName == null)
            {
                throw new ArgumentNullException("SecurityIdentifier (can only be null if DN or SamAccountName is provided)");
            }
            _sid = sid;
            _type = type;
            _dn = dn;
            _samAccountName = samAccountName;
            _isTier0 = isTier0;
            _domainRid = 0;
            _rootDomainRid = 0;
        }
    }

    public class ResultTrusteeSerializer : JsonConverter<ResultTrustee>
    {
        public override ResultTrustee Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }

        public override void Write(Utf8JsonWriter writer, ResultTrustee trustee, JsonSerializerOptions options)
        {
            writer.WriteStartObject();

            if (trustee.Dn != null)
                writer.WriteString("dn", trustee.Dn);
            if (trustee.Sid != null)
                writer.WriteString("sid", trustee.Sid.ToString());
            if (trustee.SamAccountName != null)
                writer.WriteString("samaccountname", trustee.SamAccountName);
            if (trustee.DomainRid != 0)
                writer.WriteNumber("domain_rid", trustee.DomainRid);
            if (trustee.RootDomainRid != 0)
                writer.WriteNumber("root_domain_rid", trustee.RootDomainRid);
            if (trustee.IsTier0)
                writer.WriteBoolean("is_tier0", true);

            writer.WriteEndObject();
        }
    }
}