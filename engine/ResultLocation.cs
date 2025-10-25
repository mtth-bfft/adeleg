using adeleg.engine.connector;
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace adeleg.engine
{
    [JsonConverter(typeof(ResultLocationSerializer))]
    public abstract class ResultLocation
    {
        ObjectClass _type;
        public ObjectClass Type
        {
            get
            {
                return _type;
            }
        }
        public abstract string HierarchicalDisplayName
        {
            get;
        }

        public ResultLocation(ObjectClass type)
        {
            this._type = type;
        }
    }

    public class ResultLocationSchemaDefaultSd : ResultLocation
    {
        private string _className;
        public override string HierarchicalDisplayName { get => $"Default on new {this._className} objects"; }

        public string ClassName
        {
            get
            {
                return _className;
            }
        }

        public ResultLocationSchemaDefaultSd(string className) :
            base(ObjectClass.Container)
        {
            this._className = className;
        }
    }

    public class ResultLocationDn : ResultLocation
    {
        private string _dn;
        public override string HierarchicalDisplayName { get => _dn; }
        public string Dn { get => _dn; }

        public ResultLocationDn(string dn, string mostSpecificClass)
            : base(ObjectClassHelper.FromString(mostSpecificClass, false))
        {
            this._dn = dn;
        }
    }

    public class ResultLocationDomainRelativeDn : ResultLocation
    {
        private string _domainRelativeDn;
        public override string HierarchicalDisplayName { get => _domainRelativeDn; }

        public ResultLocationDomainRelativeDn(string mostSpecificClass, string domainRelativeDn)
            : base(ObjectClassHelper.FromString(mostSpecificClass, false))
        {
            this._domainRelativeDn = domainRelativeDn;
        }
    }

    public class ResultLocationRootDomainRelativeDn : ResultLocation
    {
        private string _rootDomainRelativeDn;
        public override string HierarchicalDisplayName { get => _rootDomainRelativeDn; }

        public ResultLocationRootDomainRelativeDn(string mostSpecificClass, string rootDomainRelativeDn)
            : base(ObjectClassHelper.FromString(mostSpecificClass, false))
        {
            this._rootDomainRelativeDn = rootDomainRelativeDn;
        }
    }

    public class ResultLocationSerializer : JsonConverter<ResultLocation>
    {
        public override ResultLocation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            JsonSerializerOptions options2 = new JsonSerializerOptions(options);
            options2.AllowTrailingCommas = true;
            options2.IncludeFields = true;
            options2.PropertyNameCaseInsensitive = true;
            options2.RespectNullableAnnotations = false;

            JsonDocument jsonDoc = JsonDocument.ParseValue(ref reader);

            JsonElement element;
            if (jsonDoc.RootElement.TryGetProperty("dn", out element))
            {
               return new ResultLocationDn(element.ToString(), "container");
            }
            else
            {
                throw new InvalidDataException("Result location must contain a \"dn\" key");
            }
        }

        public override void Write(Utf8JsonWriter writer, ResultLocation location, JsonSerializerOptions options)
        {
            writer.WriteStartObject();

            if (location is ResultLocationDn dn)
            {
                writer.WriteString("dn", dn.Dn);
            }
            else if (location is ResultLocationSchemaDefaultSd schema)
            {
                writer.WriteString("default_sd_of_class", schema.ClassName);
            }
            else
            {
                throw new NotImplementedException();
            }

            writer.WriteEndObject();
        }
    }
}
