use crate::utils::pretty_print_ace;
use authz::{Ace, AceType};
use winldap::utils::get_attr_str;
use std::collections::HashSet;
use authz::{SecurityDescriptor, Sid};
use crate::{utils::{get_attr_sd, get_domain_sid}, schema::Schema};
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use windows::Win32::Networking::{Ldap::{LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID}, ActiveDirectory::{ADS_RIGHT_READ_CONTROL, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_CONTROL_ACCESS}};
use winldap::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION};

pub(crate) fn get_explicit_delegations(conn: &LdapConnection, naming_context: &str, forest_sid: &Sid, schema: &Schema, adminsdholder_sd: &SecurityDescriptor) -> Result<(), LdapError> {
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

        // Check if the owner of this object is Administrators or Domain Admins (the two
        // SIDs which get the SE_GROUP_OWNER flag)
        if !allowed_owner_sids.contains(&owner) && !allowed_owner_rids.contains(&owner.get_rid()) {
            println!(">> {} owns {}", owner, entry.dn);
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
            let mask = ace.get_mask() & !(ADS_RIGHT_READ_CONTROL.0 as u32 |
                ADS_RIGHT_ACTRL_DS_LIST.0 as u32 |
                ADS_RIGHT_DS_LIST_OBJECT.0 as u32 |
                ADS_RIGHT_DS_READ_PROP.0 as u32);
            if mask == 0 {
                continue;
            }

            const CLONEABLE_DOMAIN_CONTROLLERS_RID: u32 = 522;
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

            // Ignore cloneable DCs having the right to create a clone of themselves
            if mask == ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32 {
                if let Some(domain_sid) = &domain_sid {
                    if let AceType::AccessAllowedObject { object_type: Some(guid), .. } = &ace.type_specific {       
                        if let Some(name) = schema.control_access_names.get(guid) {
                            if ace.get_trustee() == &Sid::with_rid(domain_sid, CLONEABLE_DOMAIN_CONTROLLERS_RID) &&
                                    name.to_ascii_lowercase() == "allow a dc to create a clone of itself" {
                                continue;
                            }
                        }
                    }
                }
            }

            // Ignore rights to apply GPOs (it's not a delegation on the GPO), and to change password (everyone
            // can, since it requires knowing the current password)
            if mask == ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32 {
                if let AceType::AccessAllowedObject { object_type: Some(guid), .. } = &ace.type_specific {
                    if let Some(name) = schema.control_access_names.get(guid) {
                        if ["apply group policy", "change password"].contains(&name.to_ascii_lowercase().as_str()) {
                            continue;
                        }
                    }
                }
            }

            println!(">> {} : {}", &entry.dn, pretty_print_ace(ace, schema));
        }
    }
    Ok(())
}