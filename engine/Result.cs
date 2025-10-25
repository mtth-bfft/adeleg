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
    [JsonConverter(typeof(ResultSerializer))]
    public abstract class Result
    {
        [JsonIgnore]
        public abstract string Type { get; }

        protected ResultLocation _location;
        protected ResultTrustee _trustee;
        protected List<string> _warnings;
        protected List<string> _errors;
        protected string _text;

        // Properties used by the rest of the code
        public ResultTrustee Trustee => _trustee;
        public ResultLocation Location => _location;
        public IList<string> Warnings => _warnings;
        public IList<string> Errors => _errors;

        // Properties required by the DataGrid GUI to be able to display them as columns
        [JsonIgnore]
        public string ResourceHierarchicalDisplayName { get => _location.HierarchicalDisplayName; }
        [JsonIgnore]
        public ObjectClass LocationType { get => _location.Type; }
        [JsonIgnore]
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
        [JsonIgnore]
        public ObjectClass TrusteeType { get => _trustee.Type; }
        [JsonIgnore]
        public string Text {
            get {
                if (this._text == null)
                    throw new InvalidOperationException("Cannot display Result without a call to SetDisplayForestMetadata() first");
                return this._text;
            }
        }

        public Result(ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
        {
            this._location = location;
            this._trustee = trustee;
            this._warnings = warnings == null ? new List<string>() : new List<string>(warnings);
            this._errors = errors == null ? new List<string>() : new List<string>(errors);
            this._text = null;
        }

        public Result WithDisplayForestMetadata(ForestMetadata forestMetadata)
        {
            StringBuilder res = new StringBuilder();
            foreach (string msg in this.GetAccessDescriptionLines(forestMetadata))
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
            this._text = res.ToString().Trim();
            return this;
        }

        public abstract List<string> GetAccessDescriptionLines(ForestMetadata forestMetadata);

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
        public const string SerializedTypeName = "owner";

        [JsonPropertyOrder(0)]
        public override string Type => OwnerResult.SerializedTypeName;

        [JsonConstructor]
        public OwnerResult(ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
            : base(location, trustee, warnings, errors) { }

        public override List<string> GetAccessDescriptionLines(ForestMetadata forestMetadata)
        {
            return new List<string> { "Owns this resource, and no Owner Rights ACE limits their access (i.e. equivalent to Full Control)" };
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

        protected bool _present;
        protected bool _allow;
        protected int _flags;
        protected int _accessMask;
        protected Guid _objectType;
        protected Guid _inheritedObjectType;

        [JsonIgnore]
        public bool Present => _present;
        public bool Allow => _allow;
        public int Flags => _flags;
        public int AccessMask => _accessMask;
        public Guid ObjectType => _objectType;
        public Guid InheritedObjectType => _inheritedObjectType;

        public AceResult(bool present, bool allow, int flags, int accessMask, Guid objectType, Guid inheritedObjectType, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
            : base(location, trustee, warnings, errors)
        {
            _present = present;
            _allow = allow;
            _flags = flags;
            _accessMask = accessMask;
            _objectType = objectType;
            _inheritedObjectType = inheritedObjectType;
        }

        public AceResult(bool present, QualifiedAce ace, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
            : this(
                present,
                (ace.AceType == AceType.AccessAllowed || ace.AceType == AceType.AccessAllowedObject),
                (int)ace.AceFlags,
                (int)ace.AccessMask,
                (ace.AceType == AceType.AccessAllowedObject && (((ObjectAce)ace).ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0 ? ((ObjectAce)ace).ObjectAceType : Guid.Empty),
                (ace.AceType == AceType.AccessAllowedObject && (((ObjectAce)ace).ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0 ? ((ObjectAce)ace).InheritedObjectAceType : Guid.Empty),
                location,
                trustee,
                warnings,
                errors
            )
        {
        }

        public override List<string> GetAccessDescriptionLines(ForestMetadata forestMetadata)
        {
            List<string> accessRightsDescr = new List<string>();

            bool inherit = (this._flags & (int)AceFlags.ContainerInherit) != 0;
            bool inheritOnly = inherit && (this._flags & (int)AceFlags.InheritOnly) != 0;
            bool noPropagate = inherit && (this._flags & (int)AceFlags.NoPropagateInherit) != 0;

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

            if ((this._accessMask & ((int)ActiveDirectoryRights.CreateChild)) != 0)
            {
                // TODO: handle CreatorOwner ACE(s) in that same ACL here
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add($"Create objects of any type {createDeleteInheritDescr}");
                }
                else if (forestMetadata.schemaClassNamePerGuid.TryGetValue(this._objectType, out string className))
                {
                    accessRightsDescr.Add($"Create {className} objects {createDeleteInheritDescr}");
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.DeleteChild)) != 0)
            {
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add($"Delete any object {createDeleteInheritDescr}");
                }
                else if (forestMetadata.schemaClassNamePerGuid.TryGetValue(this._objectType, out string className))
                {
                    accessRightsDescr.Add($"Delete {className} objects {createDeleteInheritDescr}");
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.ListChildren)) != 0)
            {
                // TODO: fetch dsHeuristics for each forest, and only display this if it has any effect
                accessRightsDescr.Add("List children");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.Self)) != 0) // validated write / extended write
            {
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add("Perform all validated writes (add/remove self as member on groups, set DNS hostname and additional hostname, add/remove SPNs)");
                }
                else if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(this._objectType, out string attributeName))
                {
                    accessRightsDescr.Add($"Validated write to {attributeName}");
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.ReadProperty)) != 0)
            {
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add("Read all non-confidential properties");
                }
                else if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(this._objectType, out string attributeName))
                {
                    accessRightsDescr.Add($"Read property {attributeName}");
                }
                else if (forestMetadata.schemaPropertySetNamePerGuid.TryGetValue(this._objectType, out attributeName))
                {
                    string attributeNames = string.Join(", ", forestMetadata.schemaPropertySetMembersPerGuid[this._objectType].Select(guid => forestMetadata.schemaAttributeNamePerGuid[guid]));
                    accessRightsDescr.Add($"Read properties in {attributeName} ({attributeNames})");
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.WriteProperty)) != 0)
            {
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add("Write all properties");
                }
                else
                {
                    string attributeName;
                    if (forestMetadata.schemaAttributeNamePerGuid.TryGetValue(this._objectType, out attributeName))
                    {
                        accessRightsDescr.Add($"Write property {attributeName}");
                    }
                    else if (forestMetadata.schemaPropertySetNamePerGuid.TryGetValue(this._objectType, out attributeName))
                    {
                        string attributeNames = string.Join(", ", forestMetadata.schemaPropertySetMembersPerGuid[this._objectType].Select(guid => forestMetadata.schemaAttributeNamePerGuid[guid]));
                        accessRightsDescr.Add($"Write properties in {attributeName} ({attributeNames})");
                    }
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.DeleteTree)) != 0)
            {
                if (inherit && inheritOnly)
                    accessRightsDescr.Add("Delete objects anywhere beneath this container");
                else
                    accessRightsDescr.Add("Delete this container and objects anywhere beneath it");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.ListObject)) != 0)
            {
                // TODO: fetch dsHeuristics for each forest, and only display this if it has any effect
                accessRightsDescr.Add("View that this object exists");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.ExtendedRight)) != 0)
            {
                if (this._objectType == Guid.Empty)
                {
                    accessRightsDescr.Add("Perform all extended control operations");
                }
                else if (forestMetadata.schemaControlAccessNamePerGuid.TryGetValue(this._objectType, out string controlName))
                {
                    accessRightsDescr.Add($"Perform {controlName}");
                }
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.Delete)) != 0)
            {
                accessRightsDescr.Add("Delete this object");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.ReadControl)) != 0)
            {
                accessRightsDescr.Add("Read this object's owner and ACL");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.WriteDacl)) != 0)
            {
                accessRightsDescr.Add("Add or remove delegations on this object (equivalent to Full Control)");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.WriteOwner)) != 0)
            {
                accessRightsDescr.Add("Change this object's owner (equivalent to Full Control)");
            }
            if ((this._accessMask & ((int)ActiveDirectoryRights.AccessSystemSecurity)) != 0)
            {
                accessRightsDescr.Add("Add or remove audit rules on this object");
            }

            return accessRightsDescr;
        }
    }

    public class AceAddedResult : AceResult
    {
        public const string SerializedTypeName = "ace_added";

        [JsonPropertyOrder(0)]
        public override string Type => AceAddedResult.SerializedTypeName;

        [JsonConstructor]
        public AceAddedResult(bool Allow, int Flags, int AccessMask, Guid ObjectType, Guid InheritedObjectType, ResultLocation Location, ResultTrustee Trustee, IList<string> warnings = null, IList<string> errors = null)
            : base(true, Allow, Flags, AccessMask, ObjectType, InheritedObjectType, Location, Trustee, warnings, errors)
        {
        }

        public AceAddedResult(QualifiedAce ace, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
            : base(true, ace, location, trustee, warnings, errors)
        {
        }
    }

    public class AceMissingResult : AceResult
    {
        public const string SerializedTypeName = "ace_missing";

        [JsonPropertyOrder(0)]
        public override string Type => AceMissingResult.SerializedTypeName;

        [JsonConstructor]
        public AceMissingResult(bool allow, int flags, int accessMask, Guid objectType, Guid inheritedObjectType, ResultLocation location, ResultTrustee trustee, IList<string> warnings = null, IList<string> errors = null)
            : base(false, allow, flags, accessMask, objectType, inheritedObjectType, location, trustee, warnings, errors)
        {
        }

        public AceMissingResult(QualifiedAce ace, ResultLocation location, ResultTrustee trustee, IEnumerable<string> warnings = null, IEnumerable<string> errors = null)
            : base(false, ace, location, trustee, warnings, errors)
        {
        }
    }

    public class ResultSerializer : JsonConverter<Result>
    {
        public override Result Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            JsonSerializerOptions options2 = new JsonSerializerOptions(options);
            options2.AllowTrailingCommas = true;
            options2.IncludeFields = true;
            options2.PropertyNameCaseInsensitive = true;
            options2.RespectNullableAnnotations = false;

            using (var jsonDoc = JsonDocument.ParseValue(ref reader))
            {
                // C# can't deserialize an abstract class based on a "type" field by itself,
                // so we switch-case our subtypes ourselves.
                string typeStr = jsonDoc.RootElement.GetProperty("type").GetString();
                switch (typeStr)
                {
                    case OwnerResult.SerializedTypeName:
                        return jsonDoc.RootElement.Deserialize<OwnerResult>(options2);
                    case AceAddedResult.SerializedTypeName:
                        return jsonDoc.RootElement.Deserialize<AceAddedResult>(options2);
                    case AceMissingResult.SerializedTypeName:
                        return jsonDoc.RootElement.Deserialize<AceMissingResult>(options2);
                    default:
                        throw new JsonException($"Unsupported result type {typeStr}");
                }
            }
        }

        public override void Write(Utf8JsonWriter writer, Result result, JsonSerializerOptions options)
        {
            var options2 = new JsonSerializerOptions(options);
            options2.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            options2.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault;
            JsonSerializer.Serialize(writer, (object)result, options2);
        }
    }
}
