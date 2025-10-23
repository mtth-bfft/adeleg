using adeleg.engine.connector;
using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace adeleg.engine
{
    public abstract class Result
    {
        protected ResultLocation _location;
        protected ResultTrustee _trustee;
        protected List<string> _warnings;
        protected List<string> _errors;

        // Properties used by the rest of the code
        public ResultTrustee Trustee { get => _trustee; }
        public ResultLocation Location { get => _location; }
        public IList<string> Warnings { get => _warnings.AsReadOnly(); }
        public IList<string> Errors { get => _errors.AsReadOnly(); }

        // Properties required by the DataGrid GUI to be able to display them as columns
        public string ResourceHierarchicalDisplayName { get => _location.HierarchicalDisplayName; }
        public ObjectClass LocationType { get => _location.Type; }
        public string TrusteeHierarchicalDisplayName
        {
            get
            {
                if (_trustee.Dn != null)
                    return _trustee.Dn;
                else if (_trustee.SamAccountName != null)
                    return _trustee.SamAccountName;
                else if (_trustee.Sid != null)
                    return _trustee.Sid.ToString();
                else
                    return "(Unknown)";
            }
        }
        public ObjectClass TrusteeType { get => _trustee.Type; }
        public string Text
        {
            get
            {
                StringBuilder res = new StringBuilder();
                foreach (string msg in this.GetAccessDescriptionLines())
                {
                    res.Append(msg);
                    res.Append(Environment.NewLine);
                }
                if (_warnings.Count > 0)
                {
                    foreach (string msg in _warnings)
                    {
                        res.Append(Environment.NewLine);
                        res.Append("Warning: ");
                        res.Append(msg);
                    }
                }
                if (_errors.Count > 0)
                {
                    foreach (string msg in _errors)
                    {
                        res.Append(Environment.NewLine);
                        res.Append("Error: ");
                        res.Append(msg);
                    }
                }
                return res.ToString().Trim();
            }
        }

        public Result(ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors)
        {
            this._location = location;
            this._trustee = trustee;
            this._warnings = new List<string>(warnings);
            this._errors = new List<string>(errors);
        }

        public abstract List<string> GetAccessDescriptionLines();

        public string ToJson()
        {
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                // Don't over-escape characters like in JSON API web servers
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = true
            };
            options.Converters.Add(new ResultSerializer());
            options.Converters.Add(new ResultTrusteeSerializer());
            options.Converters.Add(new ResultLocationSerializer());
            return JsonSerializer.Serialize(this, options);
        }
    }

    public class OwnerResult : Result
    {
        public OwnerResult(ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors)
            : base(location, trustee, warnings, errors) { }

        public override List<string> GetAccessDescriptionLines()
        {
            return new List<string> { "Owns this resource, and no Owner Rights limits their access (i.e. equivalent to Full Control)" };
        }
    }

    public abstract class AceResult : Result
    {
        private const int fullControlAccessRights =
            (int)ActiveDirectoryRights.WriteDacl |
            (int)ActiveDirectoryRights.WriteOwner;
        private const int handledAccessRights =
            (int)ActiveDirectoryRights.CreateChild |
            (int)ActiveDirectoryRights.DeleteChild |
            (int)ActiveDirectoryRights.ListChildren |
            (int)ActiveDirectoryRights.Self |
            (int)ActiveDirectoryRights.ReadProperty |
            (int)ActiveDirectoryRights.WriteProperty |
            (int)ActiveDirectoryRights.DeleteTree |
            (int)ActiveDirectoryRights.ListObject |
            (int)ActiveDirectoryRights.ExtendedRight |
            (int)ActiveDirectoryRights.Delete |
            (int)ActiveDirectoryRights.ReadControl |
            (int)ActiveDirectoryRights.WriteDacl |
            (int)ActiveDirectoryRights.WriteOwner |
            (int)ActiveDirectoryRights.Synchronize |
            (int)ActiveDirectoryRights.AccessSystemSecurity;

        protected QualifiedAce _ace;
        protected List<string> _accessRightsDescr;

        public QualifiedAce Ace
        {
            get => this._ace;
        }

        public Guid ObjType
        {
            get
            {
                if (this._ace.AceType == AceType.AccessAllowedObject && (((ObjectAce)_ace).ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
                {
                    return ((ObjectAce)_ace).ObjectAceType;
                }
                else
                {
                    return Guid.Empty;
                }
            }
        }
        public Guid InheritObjType
        {
            get
            {
                if (this._ace.AceType == AceType.AccessAllowedObject && (((ObjectAce)_ace).ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
                {
                    return ((ObjectAce)_ace).InheritedObjectAceType;
                }
                else
                {
                    return Guid.Empty;
                }
            }
        }

        public AceResult(QualifiedAce ace, List<string> accessRightsDescr, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors)
            : base(location, trustee, warnings, errors)
        {
            this._ace = ace;
            this._accessRightsDescr = accessRightsDescr;
        }

        public AceResult(QualifiedAce ace, ForestMetadata forestMetadata, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors)
            : base(location, trustee, warnings, errors)
        {
            this._ace = ace;
            this._accessRightsDescr = new List<string>();

            bool inherit = ace.AceFlags.HasFlag(AceFlags.ContainerInherit);
            bool inheritOnly = inherit && ace.AceFlags.HasFlag(AceFlags.InheritOnly);
            bool noPropagate = inherit && ace.AceFlags.HasFlag(AceFlags.NoPropagateInherit);

            string createDeleteInheritDescr;
            if (inherit)
            {
                if (inheritOnly && noPropagate)
                    createDeleteInheritDescr = "in containers directly below this container";
                else if (inheritOnly && !noPropagate)
                    createDeleteInheritDescr = "in containers anywhere below this container";
                else if (!inheritOnly && noPropagate)
                    createDeleteInheritDescr = "in this container and containers directly below it";
                else
                    createDeleteInheritDescr = "anywhere below this container";
            }
            else
            {
                createDeleteInheritDescr = "directly below this container";
            }

            // TODO: specify "on this container and on AdminSdHolder-protected objects (..list..)" if resource DN is AdminSDHolder

            if ((ace.AccessMask & ((int)ActiveDirectoryRights.CreateChild)) != 0)
            {
                // TODO: handle CreatorOwner ACE(s) in that same ACL here
                if (this.ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add($"Create objects of any type {createDeleteInheritDescr}");
                    this._warnings.Add("Best practice: specify which object type can be created. This be abused to create privileged objects, see e.g.CVE - 2021 - 42291 and BadSuccessor vulnerabilities");
                }
                else
                {
                    if (forestMetadata.schemaClassNamePerGuid.TryGetValue(ObjType, out string className))
                    {
                        this._accessRightsDescr.Add($"Create {className} objects {createDeleteInheritDescr}");
                    }
                    else
                    {
                        // CreateChild with a GUID that is not a class does not allow to create any child object
                        this._warnings.Add($"Non-sense access mask: Create Child right combined with object type {ObjType} which is not a class");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.DeleteChild)) != 0)
            {
                if (ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add($"Delete any object {createDeleteInheritDescr}");
                }
                else
                {
                    if (forestMetadata.schemaClassNamePerGuid.TryGetValue(ObjType, out string className))
                    {
                        this._accessRightsDescr.Add($"Delete {className} objects {createDeleteInheritDescr}");
                    }
                    else
                    {
                        // DeleteChild with a GUID that is not a class does not allow to delete any child object
                        this._warnings.Add($"Non-sense access mask: Delete Child right combined with {ObjType} which is not a class");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.ListChildren)) != 0)
            {
                // TODO: fetch dsHeuristics for each forest, and only display this if it has any effect
                this._accessRightsDescr.Add("List children");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.Self)) != 0) // validated write / extended write
            {
                // ExtendedWrite with WriteProp is the same as WriteProp alone: no validation is enforced.
                // Warn about it if the ACE does not seem intended to grant "Full Control" (in which case, who cares)
                if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0 &&
                    (ace.AccessMask & fullControlAccessRights) != fullControlAccessRights)
                {
                    this._warnings.Add($"Non-sense access mask: ValidatedWrite along with WriteProperty is the same as no validation at all");
                }

                if (ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add("Perform all validated writes (add/remove self as member on groups, set DNS hostname and additional hostname, add/remove SPNs)");
                }
                else
                {
                    if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(ObjType, out string attributeName))
                    {
                        this._accessRightsDescr.Add($"Validated write to {attributeName}");
                    }
                    else
                    {
                        // Validated write on a non-validated attribute (or on a property set/class/controlaccessright) grants nothing
                        this._warnings.Add($"Non-sense access mask: Extended write right combined with {ObjType} which is not an attribute with validation");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.ReadProperty)) != 0)
            {
                if (ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add("Read all non-confidential properties");
                }
                else
                {
                    if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(ObjType, out string attributeName))
                    {
                        this._accessRightsDescr.Add($"Read property {attributeName}");
                    }
                    else if (forestMetadata.schemaPropertySetNamePerGuid.TryGetValue(ObjType, out attributeName))
                    {
                        string attributeNames = string.Join(", ", forestMetadata.schemaPropertySetMembersPerGuid[ObjType].Select(guid => forestMetadata.schemaAttributeNamePerGuid[guid]));
                        this._accessRightsDescr.Add($"Read properties in {attributeName} ({attributeNames})");
                    }
                    else
                    {
                        this._warnings.Add($"Non-sense access mask: Read property right combined with {ObjType} which is not an attribute");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
            {
                if (ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add("Write all properties");
                }
                else
                {
                    string attributeName;
                    if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(ObjType, out attributeName))
                    {
                        this._accessRightsDescr.Add($"Write property {attributeName}");
                    }
                    else if (forestMetadata.schemaPropertySetNamePerGuid.TryGetValue(ObjType, out attributeName))
                    {
                        string attributeNames = string.Join(", ", forestMetadata.schemaPropertySetMembersPerGuid[ObjType].Select(guid => forestMetadata.schemaAttributeNamePerGuid[guid]));
                        this._accessRightsDescr.Add($"Write properties in {attributeName} ({attributeNames})");
                    }
                    else
                    {
                        this._warnings.Add($"Non-sense access mask: Read property right combined with {ObjType} which is not an attribute");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.DeleteTree)) != 0)
            {
                if (inherit && inheritOnly)
                    this._accessRightsDescr.Add("Delete objects anywhere beneath this container");
                else
                    this._accessRightsDescr.Add("Delete this container and objects anywhere beneath it");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.ListObject)) != 0)
            {
                // TODO: fetch dsHeuristics for each forest, and only display this if it has any effect
                this._accessRightsDescr.Add("View that this object exists");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.ExtendedRight)) != 0)
            {
                if (ObjType == Guid.Empty)
                {
                    this._accessRightsDescr.Add("Perform all extended control operations");
                }
                else
                {
                    if (forestMetadata.schemaControlAccessNamePerGuid.TryGetValue(ObjType, out string controlName))
                    {
                        this._accessRightsDescr.Add($"Perform {controlName}");
                    }
                    else
                    {
                        this._warnings.Add($"Non-sense access mask: ControlAccess right combined with {ObjType} which is not an attribute");
                    }
                }
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.Delete)) != 0)
            {
                this._accessRightsDescr.Add("Delete this object");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.ReadControl)) != 0)
            {
                this._accessRightsDescr.Add("Read this object's owner and ACL");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteDacl)) != 0)
            {
                this._accessRightsDescr.Add("Add or remove delegations on this object (equivalent to Full Control)");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.WriteOwner)) != 0)
            {
                this._accessRightsDescr.Add("Change this object's owner (equivalent to Full Control)");
            }
            if ((ace.AccessMask & ((int)ActiveDirectoryRights.AccessSystemSecurity)) != 0)
            {
                this._accessRightsDescr.Add("Add or remove audit rules on this object");
            }
            if ((ace.AccessMask & handledAccessRights) != ace.AccessMask)
            {
                int unsupportedAccessMask = ace.AccessMask & ~handledAccessRights;
                this._warnings.Add($"Unsupported access rights {unsupportedAccessMask:X}");
            }
        }

        public override List<string> GetAccessDescriptionLines()
        {
            return this._accessRightsDescr;
        }
    }

    public class AceAddResult : AceResult {
        public AceAddResult(QualifiedAce ace, ForestMetadata forestMetadata, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors) :
            base(ace, forestMetadata, location, trustee, warnings, errors) { }

        public AceAddResult(QualifiedAce ace, List<string> accessRightsDescr, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors) :
            base(ace, accessRightsDescr, location, trustee, warnings, errors) { }
    }
    public class AceRemoveResult : AceResult {
        public AceRemoveResult(QualifiedAce ace, ForestMetadata forestMetadata, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors) :
            base(ace, forestMetadata, location, trustee, warnings, errors)
        { }

        public AceRemoveResult(QualifiedAce ace, List<string> accessRightsDescr, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings, IEnumerable<string> errors) :
            base(ace, accessRightsDescr, location, trustee, warnings, errors)
        { }
    }

    public class ResultSerializer : JsonConverter<Result>
    {
        public override Result Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            throw new NotImplementedException();
        }

        public override void Write(Utf8JsonWriter writer, Result result, JsonSerializerOptions options)
        {
            writer.WriteStartObject();

            writer.WritePropertyName("trustee");
            JsonConverter<ResultTrustee> trusteeConverter = (JsonConverter<ResultTrustee>)options.GetConverter(typeof(ResultTrustee));
            trusteeConverter.Write(writer, result.Trustee, options);

            writer.WritePropertyName("resource");
            JsonConverter<ResultLocation> locationConverter = (JsonConverter<ResultLocation>)options.GetConverter(typeof(ResultLocation));
            locationConverter.Write(writer, result.Location, options);

            writer.WritePropertyName("rights");
            writer.WriteStartArray();
            foreach (string right in result.GetAccessDescriptionLines())
                writer.WriteStringValue(right);
            writer.WriteEndArray();

            if (result.Warnings.Count > 0)
            {
                writer.WritePropertyName("warnings");
                writer.WriteStartArray();
                foreach (string msg in result.Warnings)
                    writer.WriteStringValue(msg);
                writer.WriteEndArray();
            }

            if (result.Errors.Count > 0)
            {
                writer.WritePropertyName("errors");
                writer.WriteStartArray();
                foreach (string msg in result.Errors)
                    writer.WriteStringValue(msg);
                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }
    }
}
