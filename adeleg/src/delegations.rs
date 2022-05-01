use authz::{Ace, AceType, Guid};
use winldap::utils::get_attr_str;
use std::collections::{HashSet, HashMap};
use authz::{SecurityDescriptor, Sid};
use serde::{Serialize, Deserialize};
use crate::{utils::{get_attr_sd, get_domain_sid}, schema::Schema};
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use windows::Win32::{Networking::{Ldap::{LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID}, ActiveDirectory::{ADS_RIGHT_READ_CONTROL, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DELETE, ADS_RIGHT_DS_DELETE_TREE}}, Security::{CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, ACE_OBJECT_TYPE_PRESENT}};
use winldap::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;
use windows::Win32::Security::NO_PROPAGATE_INHERIT_ACE;
use windows::Win32::Security::ACE_INHERITED_OBJECT_TYPE_PRESENT;
use windows::Win32::Networking::ActiveDirectory::ADS_RIGHT_DS_CONTROL_ACCESS;

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
    //TODO: Rid(u32),
    //TODO: UPN(String),
    //TODO: SamAccountName(String),
    //TODO: DN(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelegationLocation {
    // In the schema partition, in the defaultSecurityDescriptor attribute of a given class name
    DefaultSecurityDescriptor(String),
    // In a domain partition, at the given relative DN
    DomainDn(String),
    // In the configuration partition, at the given relative DN
    ConfigurationDn(String),
    // In the schema partition, at the given relative DN
    SchemaDn(String),
    // Only used for delegations which are not delegated on a particular object
    // and only use fixed_location fields in DelegationAce.
    Global,
}

impl PartialEq for DelegationLocation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DelegationLocation::DefaultSecurityDescriptor(a), DelegationLocation::DefaultSecurityDescriptor(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::DomainDn(a), DelegationLocation::DomainDn(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::ConfigurationDn(a), DelegationLocation::ConfigurationDn(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::SchemaDn(a), DelegationLocation::SchemaDn(b)) => a.to_lowercase() == b.to_lowercase(),
            (DelegationLocation::Global, DelegationLocation::Global) => true,
            _ => false,
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
            DelegationLocation::DomainDn(rdn) => {
                hasher.write_u8(2);
                rdn.to_lowercase().hash(hasher);
            },
            DelegationLocation::ConfigurationDn(rdn) => {
                hasher.write_u8(3);
                rdn.to_lowercase().hash(hasher);
            },
            DelegationLocation::SchemaDn(rdn) => {
                hasher.write_u8(4);
                rdn.to_lowercase().hash(hasher);
            },
            DelegationLocation::Global => {
                hasher.write_u8(5);
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TemplateResourceFilter {
    // An unspecified location only restricted to some object class(es)
    AnyInstanceOf(Vec<String>),
    // In the schema partition, in the defaultSecurityDescriptor attribute of a given class name
    DefaultSecurityDescriptor(String),
    // Hardcoded relative DN in the domain partition (use with parsimony)
    DomainDn(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
pub struct DelegationTemplate {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) resource: TemplateResourceFilter,
    pub(crate) rights: Vec<DelegationAce>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub(crate) trustee: DelegationTrustee,
    #[serde(rename = "template")]
    pub(crate) template_name: String,
    #[serde(skip)]
    pub(crate) template: Option<DelegationTemplate>,
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

    pub fn derive_aces(&self) -> HashMap<DelegationLocation, Vec<Ace>> {
        let mut res = HashMap::new();

        if let Some(template) = &self.template {
            for ace in &template.rights {
                let location = if let Some(fixed_location) = &ace.fixed_location {
                    fixed_location.clone()
                } else {
                    self.resource.clone()
                };
                let trustee = match &self.trustee {
                    DelegationTrustee::Sid(s) => s.clone(),
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
                let ace = Ace {
                    trustee,
                    flags,
                    access_mask: ace.access_mask,
                    type_specific,
                };
                res.entry(location).or_insert(vec![]).push(ace);
            }
        }

        res
    }
}

fn resolve_object_type(name: &str, schema: &Schema) -> Option<Guid> {
    for (guid, class_name) in &schema.class_guids {
        if class_name == name {
            return Some(guid.clone());
        }
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
    for (class_guid, class_name) in &schema.class_guids {
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
                if let Some(object_type) = &ace.object_type_name {
                    if let Some(guid) = resolve_object_type(object_type, schema) {
                        ace.object_type = Some(guid);
                    } else {
                        return Err(format!("unknown object type \"{}\"", object_type));
                    }
                }
                if let Some(inherited_object_type) = &ace.inherited_object_type_name {
                    if let Some(guid) = resolve_inherited_object_type(inherited_object_type, schema) {
                        ace.inherited_object_type = Some(guid);
                    } else {
                        return Err(format!("unknown inherited object type \"{}\"", inherited_object_type));
                    }
                }
            }
        }
        Ok(res)
    }
}

pub(crate) fn get_schema_aces(schema: &Schema, forest_sid: &Sid) -> HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> {
    let mut res = HashMap::new();
    let default_sds = schema.class_default_sd.get(forest_sid).unwrap();
    for (class_name, default_sd) in default_sds {
        if let Some(default_acl) = &default_sd.dacl {
            for ace in &default_acl.aces {
                if !is_ace_part_of_a_delegation(ace,
                        &[],
                        false,
                        &[],
                        &schema,
                        forest_sid,
                        forest_sid) {
                    continue;
                }

                res.entry(ace.trustee.clone()).or_insert(HashMap::new())
                    .entry(DelegationLocation::DefaultSecurityDescriptor(class_name.to_owned()))
                    .or_insert(vec![])
                    .push(ace.to_owned());
            }
        }
    }
    res
}

pub(crate) fn get_explicit_aces(conn: &LdapConnection, naming_context: &str, forest_sid: &Sid, schema: &Schema, adminsdholder_sd: &SecurityDescriptor) -> Result<HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>>, LdapError> {
    let domain_sid = get_domain_sid(conn, naming_context);
    let default_sd = schema.class_default_sd.get(domain_sid.as_ref().unwrap_or(forest_sid)).expect("domain SID without defaultSecurityDescriptors");
    let adminsdholder_aces: &[Ace] = adminsdholder_sd.dacl.as_ref().map(|d| &d.aces[..]).unwrap_or(&[]);

    let mut sd_control_val = BerVal::new();
    sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((DACL_SECURITY_INFORMATION.0).into())]));
    let sd_control = LdapControl::new(
        LDAP_SERVER_SD_FLAGS_OID,
        &sd_control_val,
        true)?;
    let search = LdapSearch::new(&conn, Some(naming_context), LDAP_SCOPE_SUBTREE,
                             Some("(objectClass=*)"),
                             Some(&[
        "nTSecurityDescriptor",
        "objectClass",
        "adminCount",
    ]), &[&sd_control]);

    let mut res = HashMap::new();
    for entry in search {
        let entry = entry?;
        let admincount = get_attr_str(&[&entry], &entry.dn, "admincount").unwrap_or("0".to_owned()) != "0";
        let sd = get_attr_sd(&[&entry], &entry.dn, "ntsecuritydescriptor")?;
        let dacl = sd.dacl.expect("assertion failed: object without a DACL");

        // Check if the DACL is in canonical order
        if let Err(ace) = dacl.check_canonicality() {
            eprintln!(" [!] ACL of {} is not in canonical order, fix ACE: {:?}", entry.dn, ace);
        }

        let classes = get_attr_strs(&[&entry], &entry.dn, "objectclass")?;
        let most_specific_class = &classes[classes.len() - 1];
        let default_aces: &[Ace] = default_sd.get(most_specific_class)
            .and_then(|sd| sd.dacl.as_ref().map(|acl| &acl.aces[..]))
            .unwrap_or(&[]);

        let here = if entry.dn.ends_with(conn.get_configuration_naming_context()) {
            DelegationLocation::ConfigurationDn(entry.dn.to_lowercase().replace(&format!(",{}", conn.get_configuration_naming_context().to_lowercase()), ""))
        } else if entry.dn.ends_with(conn.get_schema_naming_context()) {
            DelegationLocation::SchemaDn(entry.dn.to_lowercase().replace(&format!(",{}", conn.get_schema_naming_context().to_lowercase()), ""))
        } else {
            DelegationLocation::DomainDn(entry.dn.to_lowercase().replace(&format!(",{}", &naming_context.to_lowercase()), ""))
        };

        for ace in &dacl.aces {
            if !is_ace_part_of_a_delegation(ace,
                    &default_aces,
                    admincount,
                    &adminsdholder_aces[..],
                    &schema,
                    &domain_sid.as_ref().unwrap_or(forest_sid),
                    &forest_sid) {
                continue;
            }
            res.entry(ace.trustee.clone()).or_insert(HashMap::new())
                .entry(here.clone()).or_insert(vec![])
                .push(ace.to_owned());
        }
    }
    Ok(res)
}

pub fn is_ace_part_of_a_delegation(ace: &Ace, default_aces: &[Ace], admincount: bool, adminsdholder_aces: &[Ace], schema: &Schema, domain_sid: &Sid, forest_sid: &Sid) -> bool {
    let ignored_trustee_sids: HashSet<Sid> = HashSet::from([
        Sid::try_from("S-1-5-10").expect("invalid SID"),     // SELF
        Sid::try_from("S-1-3-0").expect("invalid SID"),      // Creator Owner
        Sid::try_from("S-1-5-18").expect("invalid SID"),     // Local System
        Sid::try_from("S-1-5-20").expect("invalid SID"),     // Network Service
        Sid::try_from("S-1-5-32-544").expect("invalid SID"), // Administrators
        Sid::try_from("S-1-5-9").expect("invalid SID"),      // Enterprise Domain Controllers
        Sid::try_from("S-1-5-32-548").expect("invalid SID"), // Account Operators
        Sid::try_from("S-1-5-32-549").expect("invalid SID"), // Server Operators
        Sid::try_from("S-1-5-32-550").expect("invalid SID"), // Print Operators
        Sid::try_from("S-1-5-32-551").expect("invalid SID"), // Backup Operators
        domain_sid.with_rid(512),                                // Domain Admins
        domain_sid.with_rid(516),                                // Domain Controllers
        forest_sid.with_rid(518),                                // Schema Admins
        forest_sid.with_rid(519),                                // Enterprise Admins
    ]);
    let ignored_control_accesses = [
        "apply group policy", // applying a group policy does not mean we control it
        "change password", // changing password requires knowing the current password
        "allow a dc to create a clone of itself", // if an attacker can impersonate a DC, cloning to a new DC is the least of your worries
    ];
    let everyone = Sid::try_from("S-1-1-0").expect("invalid SID");

    if ace.is_inherited() {
        return false; // ignore inherited ACEs
    }
    if ace.trustee == everyone && !ace.grants_access() &&
            (ace.access_mask | ADS_RIGHT_DELETE.0 as u32 | ADS_RIGHT_DS_DELETE_TREE.0 as u32) == ace.access_mask {
        return false; // ignore "delete protection" ACEs
    }
    if default_aces.contains(&ace) {
        return false; // ignore ACEs from the schema (note: the defaultSecurityDescriptor from the forest
        // schema is not inherited: it is simply memcpy()ed into the new object's security descriptor.
        // So comparison here is simple, based on a fast hash lookup.
    }
    if admincount && adminsdholder_aces.contains(&ace) {
        return false; // ignore ACEs from SDProp on objects marked with adminCount=1 (note: ACEs from
        // AdminSDHolder are not inherited, just copied, so comparison here is also a simple fast hash
        // lookup.)
    }
    if ignored_trustee_sids.contains(&ace.trustee) {
        return false; // these principals are already in control of the resource (either because they
        // are the resource itself, or because they are highly privileged over the entire forest)
    }

    // Ignore read-only ACEs which cannot be abused (e.g. to read LAPS passwords).
    let problematic_rights = ace.access_mask as i32 & !(ADS_RIGHT_READ_CONTROL.0 |
        ADS_RIGHT_ACTRL_DS_LIST.0 |
        ADS_RIGHT_DS_LIST_OBJECT.0 |
        ADS_RIGHT_DS_READ_PROP.0);
    if problematic_rights == 0 {
        return false;
    }

    // Some control accesses do not grant any right on the resource itself, they are not a delegation
    if problematic_rights == ADS_RIGHT_DS_CONTROL_ACCESS.0 {
        if let Some(guid) = ace.get_object_type() {
            if let Some(name) = schema.control_access_names.get(guid) {
                if ignored_control_accesses.contains(&name.to_lowercase().as_str()) {
                    return false;
                }
            }
        }
    }

    true
}