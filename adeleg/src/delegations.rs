use authz::{Ace, AceType, Guid};
use std::collections::HashMap;
use authz::Sid;
use serde::{Serialize, Deserialize};
use crate::{utils::{Domain, replace_suffix_case_insensitive, ends_with_case_insensitive, resolve_samaccountname_to_sid}, schema::Schema};
use winldap::connection::LdapConnection;
use windows::Win32::Security::{CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, ACE_OBJECT_TYPE_PRESENT};
use windows::Win32::Security::NO_PROPAGATE_INHERIT_ACE;
use windows::Win32::Security::ACE_INHERITED_OBJECT_TYPE_PRESENT;

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

fn true_by_default() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum DelegationTrustee {
    Sid(Sid),
    DomainRid(u32),
    RootDomainRid(u32),
    SamAccountName(String),
    //TODO: UPN(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialOrd)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum DelegationLocation {
    // In the schema partition, in the defaultSecurityDescriptor attribute of a given class name
    DefaultSecurityDescriptor(String),
    // In a partition, at the given absolute or relative DN.
    Dn(String),
    // Only used for delegations which are not delegated on a particular object
    // and only use fixed_location fields in DelegationAce.
    Global,
}

impl Default for DelegationLocation {
    fn default() -> Self {
        Self::Global
    }
}

impl PartialEq for DelegationLocation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DelegationLocation::DefaultSecurityDescriptor(a), DelegationLocation::DefaultSecurityDescriptor(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::Dn(a), DelegationLocation::Dn(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::Global, DelegationLocation::Global) => true,
            _ => false,
        }
    }
}

impl Ord for DelegationLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (DelegationLocation::Global, DelegationLocation::Global) => std::cmp::Ordering::Equal,
            (DelegationLocation::Global, _) => std::cmp::Ordering::Less,
            (_, DelegationLocation::Global) => std::cmp::Ordering::Greater,
            (DelegationLocation::DefaultSecurityDescriptor(c1), DelegationLocation::DefaultSecurityDescriptor(c2)) => c1.cmp(c2),
            (DelegationLocation::DefaultSecurityDescriptor(_), _) => std::cmp::Ordering::Less,
            (_, DelegationLocation::DefaultSecurityDescriptor(_)) => std::cmp::Ordering::Greater,
            (DelegationLocation::Dn(d1), DelegationLocation::Dn(d2)) => 
                d1.split(',').rev().collect::<Vec<&str>>().cmp(&d2.split(',').rev().collect::<Vec<&str>>()),
        }
    }
}

impl core::fmt::Display for DelegationLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationLocation::DefaultSecurityDescriptor(class_name) => f.write_fmt(format_args!("All objects of class {}", class_name)),
            DelegationLocation::Dn(dn) => f.write_str(dn),
            DelegationLocation::Global => f.write_str("Global"),
        }
    }
}

impl core::hash::Hash for DelegationLocation {
    fn hash<H>(&self, hasher: &mut H) where H: core::hash::Hasher {
        match self {
            DelegationLocation::DefaultSecurityDescriptor(class_name) => {
                hasher.write_u8(1);
                class_name.to_lowercase().hash(hasher);
            },
            DelegationLocation::Dn(dn_or_rdn) => {
                hasher.write_u8(2);
                dn_or_rdn.to_lowercase().hash(hasher);
            },
            DelegationLocation::Global => {
                hasher.write_u8(3);
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum TemplateResourceFilter {
    // This template is global, it applies to the entire forest
    Global,
    // In the schema partition, in the defaultSecurityDescriptor attribute of a given class name
    DefaultSecurityDescriptor(String),
    // An unspecified location only restricted to some object class(es)
    AnyInstanceOf(Vec<String>),
    // Hardcoded relative DN in the domain partition (use with parsimony)
    DomainDn(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DelegationAce {
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub fixed_location: Option<DelegationLocation>,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default = "true_by_default")]
    pub allow: bool,
    pub access_mask: u32,
    #[serde(skip)]
    pub object_type: Option<Guid>,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    #[serde(rename = "object_type")]
    pub object_type_name: Option<String>,
    #[serde(skip)]
    pub inherited_object_type: Option<Guid>,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    #[serde(rename = "inherited_object_type")]
    pub inherited_object_type_name: Option<String>,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub container_inherit: bool,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub object_inherit: bool,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub inherit_only: bool,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub no_propagate: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DelegationTemplate {
    pub(crate) name: String,
    pub(crate) description: String,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub(crate) resource: Option<TemplateResourceFilter>,
    pub(crate) rights: Vec<DelegationAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub(crate) trustee: DelegationTrustee,
    #[serde(rename = "template")]
    pub(crate) template_name: String,
    #[serde(skip)]
    pub(crate) template: Option<DelegationTemplate>,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    pub(crate) resource: DelegationLocation,
}

impl Delegation {
    pub fn from_json(json: &str, templates: &HashMap<String, DelegationTemplate>) -> Result<Vec<Self>, String> {
        let mut res: Vec<Self> = match serde_json::from_str(&json) {
            Ok(v) => v,
            Err(e) => return Err(e.to_string()),
        };
        for delegation in &mut res {
            if let Some(template) = templates.get(&delegation.template_name) {
                delegation.template = Some(template.clone());
            } else {
                return Err(format!("unknown template name \"{}\" referenced in delegation", delegation.template_name))
            }
        }
        Ok(res)
    }

    pub fn derive_aces(&self, conn: &LdapConnection, root_domain: &Domain, domains: &[Domain]) -> Result<HashMap<DelegationLocation, Vec<Ace>>, String> {
        let mut res = HashMap::new();

        if let Some(template) = &self.template {
            for ace in &template.rights {
                // Specialize the delegation's location and trustee, if necessary (e.g. when the trustee is identified
                // by samaccountname, resolve to a SID within the domain where the ACE will sit)
                let location = if let Some(fixed_location) = &ace.fixed_location {
                    fixed_location.clone()
                } else {
                    self.resource.clone()
                };
                let locations = if let DelegationLocation::Dn(dn_or_rdn) = location {
                    if ends_with_case_insensitive(&dn_or_rdn, "cn=configuration,dc=*") {
                        vec![DelegationLocation::Dn(replace_suffix_case_insensitive(&dn_or_rdn, "cn=configuration,dc=*", conn.get_configuration_naming_context()))]
                    } else if ends_with_case_insensitive(&dn_or_rdn, "cn=schema,dc=*") {
                        vec![DelegationLocation::Dn(replace_suffix_case_insensitive(&dn_or_rdn, "cn=schema,dc=*", conn.get_schema_naming_context()))]
                    } else if ends_with_case_insensitive(&dn_or_rdn, "dc=domaindnszones,dc=*") ||
                            ends_with_case_insensitive(&dn_or_rdn, "dc=forestdnszones,dc=*") {
                        vec![DelegationLocation::Dn(replace_suffix_case_insensitive(&dn_or_rdn, "dc=*", conn.get_root_domain_naming_context()))]
                    } else if ends_with_case_insensitive(&dn_or_rdn, "dc=*") {
                        domains.iter().map(|d| DelegationLocation::Dn(replace_suffix_case_insensitive(&dn_or_rdn, "dc=*", &d.distinguished_name))).collect()
                    } else {
                        vec![DelegationLocation::Dn(dn_or_rdn)]
                    }
                } else {
                    vec![location]
                };
                for location in locations {
                    let trustees = match &self.trustee {
                        DelegationTrustee::Sid(s) => vec![s.clone()],
                        DelegationTrustee::DomainRid(r) => {
                            match &location {
                                DelegationLocation::DefaultSecurityDescriptor(_) |
                                    DelegationLocation::Global => vec![root_domain.sid.with_rid(*r)],
                                DelegationLocation::Dn(dn) => {
                                    let mut domain = None;
                                    for d in domains {
                                        if ends_with_case_insensitive(dn, &d.distinguished_name) {
                                            domain = Some(d);
                                            break;
                                        }
                                    }
                                    vec![domain.unwrap_or(&root_domain).sid.with_rid(*r)]
                                },
                            }
                        },
                        DelegationTrustee::RootDomainRid(r) => vec![root_domain.sid.with_rid(*r)],
                        DelegationTrustee::SamAccountName(samaccountname) => {
                            let domain = match &location {
                                DelegationLocation::DefaultSecurityDescriptor(_) |
                                    DelegationLocation::Global => root_domain,
                                DelegationLocation::Dn(dn) => {
                                    let mut domain = None;
                                    for d in domains {
                                        if ends_with_case_insensitive(dn, &d.distinguished_name) {
                                            domain = Some(d);
                                            break;
                                        }
                                    }
                                    domain.unwrap_or(&root_domain)
                                },
                            };
                            if let Ok(sid) = resolve_samaccountname_to_sid(conn, samaccountname, domain) {
                                vec![sid]
                            } else {
                                return Err(format!("unresolved SamAccountName \"{}\\{}\" in {}",
                                                   domain.netbios_name, samaccountname, domain.distinguished_name));
                            }
                        },
                    };

                    let mut flags = 0;
                    if ace.container_inherit {
                        flags |= CONTAINER_INHERIT_ACE.0 as u8;
                    }
                    if ace.object_inherit {
                        flags |= OBJECT_INHERIT_ACE.0 as u8;
                    }
                    if ace.inherit_only {
                        flags |= INHERIT_ONLY_ACE.0 as u8;
                    }
                    if ace.no_propagate {
                        flags |= NO_PROPAGATE_INHERIT_ACE.0 as u8;
                    }
                    let type_specific = match (ace.allow, ace.object_type, ace.inherited_object_type) {
                        (true, None, None) => AceType::AccessAllowed,
                        (true, object_type, inherited_object_type) => AceType::AccessAllowedObject {
                            flags: if object_type.is_some() { ACE_OBJECT_TYPE_PRESENT.0 } else { 0 } | if inherited_object_type.is_some() { ACE_INHERITED_OBJECT_TYPE_PRESENT.0 } else { 0 },
                            object_type,
                            inherited_object_type,
                        },
                        (false, None, None) => AceType::AccessDenied,
                        (false, object_type, inherited_object_type) => AceType::AccessDeniedObject {
                            flags: if object_type.is_some() { ACE_OBJECT_TYPE_PRESENT.0 } else { 0 } | if inherited_object_type.is_some() { ACE_INHERITED_OBJECT_TYPE_PRESENT.0 } else { 0 },
                            object_type,
                            inherited_object_type,
                        },
                    };
                    for trustee in trustees {
                        res.entry(location.clone()).or_insert(vec![]).push(Ace {
                            trustee,
                            flags,
                            access_mask: ace.access_mask,
                            type_specific: type_specific.clone(),
                        });
                    }
                }
            }
        }

        Ok(res)
    }
}

fn resolve_object_type(name: &str, schema: &Schema) -> Option<Guid> {
    if let Some(guid) = schema.class_guids.get(name) {
        return Some(guid.clone());
    }
    for (guid, attr_name) in &schema.attribute_guids {
        if attr_name == name {
            return Some(guid.clone());
        }
    }
    for (guid, propset_name) in &schema.property_set_names {
        if propset_name == name {
            return Some(guid.clone());
        }
    }
    for (guid, validated_write_name) in &schema.validated_write_names {
        if validated_write_name == name {
            return Some(guid.clone());
        }
    }
    for (guid, controlaccess_name) in &schema.control_access_names {
        if controlaccess_name == name {
            return Some(guid.clone());
        }
    }
    if let Ok(guid) = Guid::try_from(name) {
        return Some(guid);
    }
    None
}

fn resolve_inherited_object_type(name: &str, schema: &Schema) -> Option<Guid> {
    for (class_name, class_guid) in &schema.class_guids {
        if class_name == name {
            return Some(class_guid.clone());
        }
    }
    if let Ok(guid) = Guid::try_from(name) {
        return Some(guid);
    }
    None
}

impl DelegationTemplate {
    pub fn from_json(json: &str, schema: &Schema) -> Result<Vec<Self>, String> {
        let mut res: Vec<DelegationTemplate> = serde_json::from_str(json).map_err(|e| format!("unable to parse template: {}", e))?;
        for template in &mut res {
            for ace in &mut template.rights {
                // Do not fail if one of these class/attribute GUIDs fails to resolve: it simply means
                // the schema has not been updated to support them. Just ignore these ACEs.
                if let Some(object_type) = &ace.object_type_name {
                    if let Some(guid) = resolve_object_type(object_type, schema) {
                        ace.object_type = Some(guid);
                    } else {
                        continue;
                    }
                }
                if let Some(inherited_object_type) = &ace.inherited_object_type_name {
                    if let Some(guid) = resolve_inherited_object_type(inherited_object_type, schema) {
                        ace.inherited_object_type = Some(guid);
                    } else {
                        continue;
                    }
                }
            }
        }
        Ok(res)
    }
}
