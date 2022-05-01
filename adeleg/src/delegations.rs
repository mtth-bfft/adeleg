use authz::{Ace, AceType, Guid};
use winldap::utils::get_attr_str;
use std::collections::{HashSet, HashMap};
use authz::{SecurityDescriptor, Sid};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use crate::{utils::{get_attr_sd, get_domain_sid}, schema::Schema};
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use windows::Win32::Networking::{Ldap::{LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID}, ActiveDirectory::{ADS_RIGHT_READ_CONTROL, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_CONTROL_ACCESS}};
use winldap::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::DACL_SECURITY_INFORMATION;

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
    Rid(u32),
    UPN(String),
    SamAccountName(String),
    DN(String),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DelegationLocation {
    // In the schema partition, in the defaultSecurityDescriptor attribute of a given class name
    DefaultSecurityDescriptor(String),
    // In the domain partition, at the given relative DN
    DomainDn(String),
    // Only used for delegations which are not delegated on a particular object
    // and only use fixed_location fields in DelegationAce.
    Global,
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
    pub fn from_json(json: &str) -> Result<Vec<Self>, String> {
        match serde_json::from_str(&json) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.to_string()),
        }
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
        for mut template in &mut res {
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

    pub fn to_json(&self, schema: &Schema) -> String {
        let mut json = serde_json::to_string_pretty(self).expect("unable to serialize");
        for ace in &self.rights {
            if let Some(guid) = &ace.object_type {
                if let Some(name) = schema.control_access_names.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.property_set_names.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.attribute_guids.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.class_guids.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
            }
            if let Some(guid) = &ace.inherited_object_type {
                if let Some(name) = schema.control_access_names.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.property_set_names.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.attribute_guids.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
                else if let Some(name) = schema.class_guids.get(guid) {
                    json = json.replace(guid.to_string().as_str(), name);
                }
            }
        }
        json
    }
}

/*
impl Delegation {
    pub fn from_template(aces: &[(DelegationLocation, Ace)], model: &DelegationTemplate) -> Vec<Self> {
        let mut res = vec![];
        let mut unmatched_aces = aces.to_vec();

        for (unmatched_location, unmatched_ace) in unmatched_aces.into_iter() {
            res.push(
                Delegation {
                    trustee: DelegationTrustee::Sid(trustee.to_owned()),
                    model: DelegationModel {
                        name: "Unknown".to_owned(),
                        parts: vec![DelegationAce {
                            access_mask: todo!(),
                            object_type: todo!(),
                            inherited_object_type: todo!(),
                            fixed_location: Some(unmatched_location),
                            container_inherit: unmatched_ace.get_container_inherit(),
                            object_inherit: todo!(),
                            inherit_only: todo!(),
                            no_propagate: todo!()
                        }],
                    },
                    location: unmatched_location,
                }
            );
        }
        res
    }
}
*/

pub(crate) fn get_schema_aces(schema: &Schema, forest_sid: &Sid) -> HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> {
    // TODO: replace with a computation at startup, enumerate subdomains, expand to a list of SIDs privileged at forest level
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
    ]);
    let ignored_trustee_rids = HashSet::from([
        512, // Domain Admins
        516, // Domain Controllers
        518, // Schema Admins
        519, // Enterprise Admins
    ]);

    let mut res = HashMap::new();

    let default_sds = schema.class_default_sd.get(forest_sid).unwrap();
    for (class_name, default_sd) in default_sds {
        if let Some(default_acl) = &default_sd.dacl {
            for ace in &default_acl.aces {
                if !ace.grants_access() {
                    continue; // ignore deny ACEs for now
                }
                if ignored_trustee_sids.contains(ace.get_trustee()) {
                    continue;
                }
                if ignored_trustee_rids.contains(&ace.get_trustee().get_rid()) {
                    continue;
                }
    
                // Ignore read-only ACEs which cannot be abused (e.g. to read LAPS passwords).
                let mask = ace.get_mask() & !(ADS_RIGHT_READ_CONTROL.0 as u32 |
                    ADS_RIGHT_ACTRL_DS_LIST.0 as u32 |
                    ADS_RIGHT_DS_LIST_OBJECT.0 as u32 |
                    ADS_RIGHT_DS_READ_PROP.0 as u32);

                if mask == 0 {
                    continue;
                }

                res.entry(ace.get_trustee().to_owned()).or_insert(HashMap::new())
                    .entry(DelegationLocation::DefaultSecurityDescriptor(class_name.to_owned()))
                    .or_insert(vec![])
                    .push(ace.to_owned());
            }
        }
    }
    res
}

pub(crate) fn get_explicit_aces(conn: &LdapConnection, naming_context: &str, forest_sid: &Sid, schema: &Schema, adminsdholder_sd: &SecurityDescriptor) -> Result<HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>>, LdapError> {
    let allowed_control_accesses = [
        "apply group policy", // applying a group policy does not mean we control it
        "change password", // changing password requires knowing the current password
        "allow a dc to create a clone of itself", // if an attacker can impersonate a DC, cloning to a new DC is the least of your worries
    ];

    let domain_sid = get_domain_sid(conn, naming_context);
    let default_sd = schema.class_default_sd.get(domain_sid.as_ref().unwrap_or(forest_sid)).expect("domain SID without defaultSecurityDescriptors");

    // Get a list of ignored ACE trustees, which can already compromise the entire domain anyway,
    // either generically or often enough that we recommend to leave the group empty in another
    // audit check.
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
    ]);
    let ignored_trustee_rids = HashSet::from([
        512, // Domain Admins
        516, // Domain Controllers
        518, // Schema Admins
        519, // Enterprise Admins
    ]);

    let adminsdholder_aces: HashSet<Ace> = HashSet::from_iter(adminsdholder_sd.dacl.as_ref().unwrap().aces.iter().cloned());

    let mut res = HashMap::new();

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
    for entry in search {
        let entry = entry?;
        let admincount = get_attr_str(&[&entry], &entry.dn, "admincount").unwrap_or("0".to_owned());
        let sd = get_attr_sd(&[&entry], &entry.dn, "ntsecuritydescriptor")?;
        let dacl = sd.dacl.expect("assertion failed: object without a DACL");

        // Check if the DACL is in canonical order
        if let Err(ace) = dacl.check_canonicality() {
            eprintln!(" [!] ACL of {} is not in canonical order, fix ACE: {:?}", entry.dn, ace);
        }

        let classes = get_attr_strs(&[&entry], &entry.dn, "objectclass")?;
        let most_specific_class = &classes[classes.len() - 1];
        let default_aces = {
            let mut aces = HashSet::new();
            if let Some(default_sd) = default_sd.get(most_specific_class) {
                if let Some(default_dacl) = &default_sd.dacl {
                    aces.extend(&default_dacl.aces);
                }
            }
            aces
        };

        for ace in &dacl.aces {
            if !ace.grants_access() {
                continue; // ignore deny ACEs for now
            }
            if ace.is_inherited() {
                continue; // ignore inherited ACEs
            }
            // The defaultSecurityDescriptor from the forest schema is not inherited: it is
            // simply memcpy()ed into the new object's security descriptor. So comparison here is
            // simple, based on a fast hash lookup.
            if default_aces.contains(ace) {
                continue; // ignore ACEs from the schema
            }
            // ACEs from AdminSDHolder are not inherited, just copied, so comparison here is also
            // a simple fast hash lookup.
            if admincount == "1" && adminsdholder_aces.contains(ace) {
                continue; // tolerate ACEs from SDProp on objects marked with adminCount=1
            }
            if ignored_trustee_sids.contains(ace.get_trustee()) {
                continue;
            }
            if ignored_trustee_rids.contains(&ace.get_trustee().get_rid()) {
                continue;
            }

            // Ignore read-only ACEs which cannot be abused (e.g. to read LAPS passwords).
            let mut mask = ace.get_mask() as i32 & !(ADS_RIGHT_READ_CONTROL.0 |
                ADS_RIGHT_ACTRL_DS_LIST.0 |
                ADS_RIGHT_DS_LIST_OBJECT.0 |
                ADS_RIGHT_DS_READ_PROP.0);

            // Ignore control access rights which cannot be abused
            if (mask & ADS_RIGHT_DS_CONTROL_ACCESS.0) != 0 {
                if let AceType::AccessAllowedObject { object_type: Some(guid), .. } = &ace.type_specific {
                    if let Some(name) = schema.control_access_names.get(guid) {
                        if allowed_control_accesses.contains(&name.to_ascii_lowercase().as_str()) {
                            mask -= ADS_RIGHT_DS_CONTROL_ACCESS.0;
                        }
                    }
                }
            }

            const KEY_ADMINS_RID: u32 = 526;
            const ENTEPRISE_KEY_ADMINS_RID: u32 = 527;

            // Ignore Key Admins having full rights on the msDS-KeyCredentialLink attribute or on the Keys container
            let null_sid = Sid::try_from("S-1-0-0").unwrap();
            if ace.get_trustee().get_rid() == ENTEPRISE_KEY_ADMINS_RID ||
                    ace.get_trustee() == &Sid::with_rid(domain_sid.as_ref().unwrap_or(&null_sid), KEY_ADMINS_RID) {
                if entry.dn.to_ascii_lowercase() == format!("CN=Keys,{}", naming_context).to_ascii_lowercase() {
                    continue;
                }
                if let AceType::AccessAllowedObject { object_type: Some(guid), .. } = &ace.type_specific {
                    if let Some(name) = schema.attribute_guids.get(guid) {
                        if name.to_ascii_lowercase() == "msds-keycredentiallink" {
                            continue;
                        }
                    }
                }
            }

            if mask == 0 {
                continue;
            }

            res.entry(ace.get_trustee().to_owned()).or_insert(HashMap::new())
                .entry(DelegationLocation::DomainDn(entry.dn.to_owned()))
                .or_insert(vec![])
                .push(ace.to_owned());
        }
    }
    Ok(res)
}