use authz::Ace;
use winldap::utils::get_attr_str;
use std::collections::{HashMap, HashSet};
use authz::{SecurityDescriptor, Sid};
use crate::utils::get_attr_sd;
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use winldap::error::LdapError;
use winldap::search::LdapSearch;
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID};
use winldap::control::{LdapControl, BerVal, BerEncodable};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION};

pub(crate) fn get_explicit_delegations(conn: &LdapConnection, naming_context: &str, default_sds: &HashMap<String, SecurityDescriptor>, adminsdholder_sd: &SecurityDescriptor) -> Result<(), LdapError> {
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
        let default_aces = {
            let mut aces = HashSet::new();
            for class in &classes {
                if let Some(default_sd) = default_sds.get(class) {
                    if let Some(default_dacl) = &default_sd.dacl {
                        aces.extend(&default_dacl.aces);
                    }
                }
            }
            aces
        };
        // The defaultSecurityDescriptor from the forest schema is not inherited: it is
        // simply memcpy()ed into the new object's security descriptor. So comparison here is
        // simple.
        for ace in &dacl.aces {
            if !ace.grants_access() {
                continue; // ignore deny ACEs for now
            }
            if ace.is_inherited() {
                continue; // ignore inherited ACEs
            }
            if default_aces.contains(ace) {
                continue; // ignore ACEs from the schema
            }
            // FIXME: ACEs from AdminSDHolder are inherited, not just copied. We need to apply a transformation
            // to the entry's object type, which may generate 2 ACEs, and compare them.
            if admincount == "1" && adminsdholder_aces.contains(ace) {
                continue; // tolerate ACEs from SDProp on objects marked with adminCount=1
            }
            if ace.get_trustee().get_rid() == 519 {
                continue; // ignore ACEs for Enterprise Admins, which have explicit ACEs in the Configuration partition
            }
            println!(">> {} on {}", ace.get_trustee(), &entry.dn);
        }
    }
    Ok(())
}