use authz::{Ace, AceType, Guid};
use winldap::utils::get_attr_str;
use std::collections::HashSet;
use authz::{SecurityDescriptor, Sid};
use serde::Serialize;
use crate::{utils::{get_attr_sd, get_domain_sid}, schema::Schema};
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use windows::Win32::Networking::{Ldap::{LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID}, ActiveDirectory::{ADS_RIGHT_READ_CONTROL, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_CONTROL_ACCESS}};
use winldap::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION};

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[derive(Debug, Serialize)]
pub enum DelegationTrustee {
    Sid(Sid),
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum DelegationLocation {
    // defaultSecurityDescriptor of a given class name, in the schema partition
    DefaultSecurityDescriptor(String),
    DN(String),
}

#[derive(Debug, Serialize)]
pub enum DelegationRights {
    Ownership,
    Ace {
        access_mask: u32,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        container_inherit: bool,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        object_inherit: bool,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        inherit_only: bool,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        no_propagate: bool,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        object_type: Option<Guid>,
        #[serde(skip_serializing_if = "is_default")]
        #[serde(default)]
        inherited_object_type: Option<Guid>,
    },
}

#[derive(Debug, Serialize)]
pub struct DelegationTemplatePart {
    rights: DelegationRights,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    location: Option<DelegationLocation>,
}

pub type DelegationTemplate = Vec<DelegationTemplatePart>;

#[derive(Debug, Serialize)]
pub struct Delegation {
    trustee: DelegationTrustee,
    template: DelegationTemplate,
    #[serde(skip_serializing_if = "is_default")]
    #[serde(default)]
    locations: Vec<DelegationLocation>,
}

pub(crate) fn get_schema_delegations(schema: &Schema, forest_sid: &Sid) -> Vec<Delegation> {
    // TODO: replace with a computation at startup, enumerate subdomains, expand to a list of SIDs privileged at forest level
    let allowed_owner_sids: HashSet<Sid> = HashSet::from([
        Sid::from_str("S-1-5-18").expect("invalid SID"), // LocalSystem is owner of system objects
        Sid::from_str("S-1-5-32-544").expect("invalid SID"), // objects created by Administrators members are owned by Administrators
    ]);
    let allowed_owner_rids = HashSet::from([
        500, // the builtin Administrator account should never be de-privileged, don't flag it
        512, // objects created by Domain Admins members are owned by Domain Admins
        518, // Schema admins
        519, // Enterprise Admins
    ]);
    let ignored_trustee_sids: HashSet<Sid> = HashSet::from([
        Sid::from_str("S-1-5-10").expect("invalid SID"),     // SELF
        Sid::from_str("S-1-3-0").expect("invalid SID"),      // Creator Owner
        Sid::from_str("S-1-5-18").expect("invalid SID"),     // Local System
        Sid::from_str("S-1-5-20").expect("invalid SID"),     // Network Service
        Sid::from_str("S-1-5-32-544").expect("invalid SID"), // Administrators
        Sid::from_str("S-1-5-9").expect("invalid SID"),      // Enterprise Domain Controllers
        Sid::from_str("S-1-5-32-548").expect("invalid SID"), // Account Operators
        Sid::from_str("S-1-5-32-549").expect("invalid SID"), // Server Operators
        Sid::from_str("S-1-5-32-550").expect("invalid SID"), // Print Operators
        Sid::from_str("S-1-5-32-551").expect("invalid SID"), // Backup Operators
    ]);
    let ignored_trustee_rids = HashSet::from([
        512, // Domain Admins
        516, // Domain Controllers
        518, // Schema Admins
        519, // Enterprise Admins
    ]);

    let mut res = vec![];

    let default_sds = schema.class_default_sd.get(forest_sid).unwrap();
    for (class_name, default_sd) in default_sds {
        if let Some(default_owner) = &default_sd.owner {
            if !allowed_owner_sids.contains(default_owner) && !allowed_owner_rids.contains(&default_owner.get_rid()) {
                res.push(Delegation {
                    trustee: DelegationTrustee::Sid(default_owner.to_owned()),
                    template: vec![
                        DelegationTemplatePart {
                            rights: DelegationRights::Ownership,
                            location: Some(DelegationLocation::DefaultSecurityDescriptor(class_name.to_owned())),
                        }
                    ],
                    locations: vec![],
                });
            }
        }

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

                res.push(Delegation {
                    trustee: DelegationTrustee::Sid(ace.get_trustee().to_owned()),
                    template: vec![
                        DelegationTemplatePart {
                            rights: DelegationRights::Ace {
                                access_mask: ace.get_mask(),
                                container_inherit: ace.get_container_inherit(),
                                object_inherit: ace.get_object_inherit(),
                                inherit_only: ace.get_inherit_only(),
                                no_propagate: ace.get_no_propagate(),
                                object_type: ace.get_object_type().copied(),
                                inherited_object_type: ace.get_inherited_object_type().copied(),
                            },
                            location: Some(DelegationLocation::DefaultSecurityDescriptor(class_name.to_owned())),
                        }
                    ],
                    locations: vec![],
                });
            }
        }
    }
    res
}

pub(crate) fn get_explicit_delegations(conn: &LdapConnection, naming_context: &str, forest_sid: &Sid, schema: &Schema, adminsdholder_sd: &SecurityDescriptor) -> Result<Vec<Delegation>, LdapError> {
    // Get a list of legitimate object owners, which are highly-privileged groups
    // or principals which can compromise the entire forest in all cases.
    let allowed_owner_sids: HashSet<Sid> = HashSet::from([
        Sid::from_str("S-1-5-18").expect("invalid SID"), // LocalSystem is owner of system objects
        Sid::from_str("S-1-5-32-544").expect("invalid SID"), // objects created by Administrators members are owned by Administrators
    ]);
    let allowed_owner_rids = HashSet::from([
        500, // the builtin Administrator account should never be de-privileged, don't flag it
        512, // objects created by Domain Admins members are owned by Domain Admins
        518, // Schema admins
        519, // Enterprise Admins
    ]);
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
        Sid::from_str("S-1-5-10").expect("invalid SID"),     // SELF
        Sid::from_str("S-1-3-0").expect("invalid SID"),      // Creator Owner
        Sid::from_str("S-1-5-18").expect("invalid SID"),     // Local System
        Sid::from_str("S-1-5-20").expect("invalid SID"),     // Network Service
        Sid::from_str("S-1-5-32-544").expect("invalid SID"), // Administrators
        Sid::from_str("S-1-5-9").expect("invalid SID"),      // Enterprise Domain Controllers
        Sid::from_str("S-1-5-32-548").expect("invalid SID"), // Account Operators
        Sid::from_str("S-1-5-32-549").expect("invalid SID"), // Server Operators
        Sid::from_str("S-1-5-32-550").expect("invalid SID"), // Print Operators
        Sid::from_str("S-1-5-32-551").expect("invalid SID"), // Backup Operators
    ]);
    let ignored_trustee_rids = HashSet::from([
        512, // Domain Admins
        516, // Domain Controllers
        518, // Schema Admins
        519, // Enterprise Admins
    ]);

    let adminsdholder_aces: HashSet<Ace> = HashSet::from_iter(adminsdholder_sd.dacl.as_ref().unwrap().aces.iter().cloned());

    let mut res = vec![];

    let mut sd_control_val = BerVal::new();
    sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0).into())]));
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
        let owner = sd.owner.expect("assertion failed: object without an owner");
        let dacl = sd.dacl.expect("assertion failed: object without a DACL");

        // Check if the DACL is in canonical order
        if let Err(ace) = dacl.check_canonicality() {
            eprintln!(" [!] ACL of {} is not in canonical order, fix ACE: {:?}", entry.dn, ace);
        }

        // Check if the owner of this object is Administrators or Domain Admins (the two
        // SIDs which get the SE_GROUP_OWNER flag)
        if !allowed_owner_sids.contains(&owner) && !allowed_owner_rids.contains(&owner.get_rid()) {
            res.push(Delegation {
                trustee: DelegationTrustee::Sid(owner.to_owned()),
                template: vec![
                    DelegationTemplatePart {
                        rights: DelegationRights::Ownership,
                        location: None,
                    }
                ],
                locations: vec![DelegationLocation::DN(entry.dn.to_owned())],
            });
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
            let null_sid = Sid::from_str("S-1-0-0").unwrap();
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

            res.push(Delegation {
                trustee: DelegationTrustee::Sid(ace.get_trustee().to_owned()),
                template: vec![
                    DelegationTemplatePart {
                        rights: DelegationRights::Ace {
                            access_mask: ace.get_mask(),
                            container_inherit: ace.get_container_inherit(),
                            object_inherit: ace.get_object_inherit(),
                            inherit_only: ace.get_inherit_only(),
                            no_propagate: ace.get_no_propagate(),
                            object_type: ace.get_object_type().copied(),
                            inherited_object_type: ace.get_inherited_object_type().copied(),
                        },
                        location: None,
                    }
                ],
                locations: vec![DelegationLocation::DN(entry.dn.to_owned())],
            });
        }
    }
    Ok(res)
}