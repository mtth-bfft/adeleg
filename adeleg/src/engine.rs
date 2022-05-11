use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_WRITE_DAC, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_DELETE, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_CREATE_CHILD, ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_DS_SELF};
use winldap::connection::LdapConnection;
use winldap::utils::get_attr_strs;
use std::collections::{HashMap, HashSet};
use crate::delegations::{Delegation, DelegationTemplate, DelegationLocation, get_explicit_aces, get_schema_aces};
use crate::utils::{Domain, get_domains, get_adminsdholder_aces, pretty_print_ace, get_attr_sid, ends_with_case_insensitive, replace_suffix_case_insensitive, capitalize};
use crate::schema::Schema;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_BASE, LDAP_SCOPE_SUBTREE};
use authz::{Sid, Ace, Guid};

pub(crate) struct Engine<'a> {
    ldap: &'a LdapConnection,
    pub(crate) domains: Vec<Domain>,
    root_domain: Domain,
    schema: Schema,
    ignored_trustee_sids: HashSet<Sid>,
    pub(crate) templates: HashMap<String, DelegationTemplate>,
    pub(crate) delegations: Vec<Delegation>,
}

impl<'a> Engine<'a> {
    pub fn new(ldap: &'a LdapConnection) -> Self {
        let domains = match get_domains(&ldap) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Unable to list domains: {}", e);
                std::process::exit(1);
            }
        };

        let root_domain = {
            let root_nc = ldap.get_root_domain_naming_context();
            let mut res = None;
            for domain in &domains {
                if domain.distinguished_name == root_nc {
                    res = Some(domain.clone());
                    break;
                }
            }
            if let Some(d) = res {
                d
            } else {
                eprintln!("Unable to find root domain naming context on this domain controller");
                std::process::exit(1);
            }
        };
    
        let domain_sids: Vec<Sid> = domains.iter().map(|d| d.sid.clone()).collect();
        let schema = match Schema::query(&ldap, &domain_sids[..], &root_domain.sid) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Unable to fetch required information from schema: {}", e);
                std::process::exit(1);
            }
        };

        // Derive a list of trustees to ignore
        let mut ignored_trustee_sids: HashSet<Sid> = HashSet::from([
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
        for domain in domains.iter() {
            ignored_trustee_sids.insert(domain.sid.with_rid(512));   // Domain Admins
            ignored_trustee_sids.insert(domain.sid.with_rid(516));   // Domain Controllers
            ignored_trustee_sids.insert(domain.sid.with_rid(518));   // Schema Admins
            ignored_trustee_sids.insert(domain.sid.with_rid(519));   // Enterprise Admins
        }

        Self {
            ldap,
            domains,
            root_domain,
            schema,
            ignored_trustee_sids,
            templates: HashMap::new(),
            delegations: Vec::new(),
        }
    }

    pub fn register_template(&mut self, template_path: &str) -> Result<(), String> {
        let json = match std::fs::read_to_string(template_path) {
            Ok(f) => f,
            Err(e) => return Err(format!("Unable to open file {} : {}", template_path, e)),
        };
        let templates = match DelegationTemplate::from_json(&json, &self.schema) {
            Ok(v) => v,
            Err(e) => return Err(format!("Unable to parse template file {} : {}", template_path, e)),
        };
        for template in templates.into_iter() {
            self.templates.insert(template.name.to_owned(), template);
        }
        Ok(())
    }

    pub fn register_delegation(&mut self, delegation_path: &str) -> Result<(), String> {
        let json = match std::fs::read_to_string(delegation_path) {
            Ok(f) => f,
            Err(e) => return Err(format!("Unable to open file {} : {}", delegation_path, e)),
        };
        let delegations = match Delegation::from_json(&json, &self.templates) {
            Ok(v) => v,
            Err(e) => return Err(format!("Unable to parse delegation file {} : {}", delegation_path, e)),
        };
        for delegation in delegations.into_iter() {
            self.delegations.push(delegation);
        }
        Ok(())
    }

    pub fn split_trustee_components(&self, trustee: &str) -> Vec<String> {
        if trustee.contains(",") {
            for domain in &self.domains {
                if ends_with_case_insensitive(&trustee, &domain.distinguished_name) {
                    let mut parts = vec![domain.distinguished_name.clone()];
                    let trustee = replace_suffix_case_insensitive(&trustee, &domain.distinguished_name, "");
                    for part in trustee.trim_matches(',').split(',').rev() {
                        parts.push(part.to_owned());
                    }
                    return parts;
                }
            }
        }
        vec![trustee.to_owned()]
    }

    // Results are indexed by trustee (Sid) -> then location -> (delegations in place, delegations missing, orphan ACEs found)
    pub fn run(&self) -> HashMap<Sid, HashMap<DelegationLocation, (Vec<Delegation>, Vec<Delegation>, Vec<Ace>)>> {
        // Derive expected ACEs from these delegations, and index these ACEs by Sid then Location
        let mut delegations_in_input: HashMap<Sid, HashMap<DelegationLocation, Vec<(Delegation, Vec<Ace>)>>> = HashMap::new();
        for delegation in &self.delegations {
            let expected_aces = match delegation.derive_aces(&self.ldap, &self.root_domain, &self.domains) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(" [!] Unable to compute expected ACEs from delegation: {}", e);
                    std::process::exit(1);
                }
            };
            for (location, aces) in expected_aces {
                let sid = aces.get(0).expect("delegations should have at least one ACE").trustee.clone();
                delegations_in_input.entry(sid).or_insert(HashMap::new())
                    .entry(location).or_insert(vec![])
                    .push((delegation.clone(), aces));
            }
        }

        // Fetch all meaningful ACEs
        let mut aces_found: HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> = get_schema_aces(&self.schema, &self.root_domain.sid, &self.ignored_trustee_sids);
        let mut naming_contexts = Vec::from(self.ldap.get_naming_contexts());
        naming_contexts.sort();

        for naming_context in naming_contexts {
            let adminsdholder_aces = match get_adminsdholder_aces(&self.ldap, &naming_context, &self.domains, &self.root_domain) {
                Ok(aces) => aces,
                Err(e) => {
                    eprintln!(" [!] Unable to fetch AdminSDHolder, {} (results will be incomplete)", e);
                    vec![]
                }
            };
        
            println!("Fetching security descriptors of naming context {}", naming_context);
            match get_explicit_aces(&self.ldap, &naming_context, &self.root_domain.sid, &self.schema, &adminsdholder_aces[..], &self.ignored_trustee_sids) {
                Ok( sids) => {
                    for (sid, locations) in sids.into_iter() {
                        for (location, mut aces) in locations.into_iter() {
                            aces_found.entry(sid.clone()).or_insert(HashMap::new())
                                .entry(location).or_insert(vec![])
                                .append(&mut aces);
                        }
                    }
                },
                Err(e) => {
                    eprintln!(" [!] Error when fetching security descriptors of naming context {} : {}", naming_context, e);
                    std::process::exit(1);
                },
            };
        }

        // Now, compare found ACEs to "expected" delegations, which gives us a list of delegations in place and orphan ACEs.
        // In the end, add a list of delegations expected but not found, and you have the entire set of results.
        let mut res: HashMap<Sid, HashMap<DelegationLocation, (Vec<Delegation>, Vec<Delegation>, Vec<Ace>)>> = HashMap::new();

        for (trustee, expected_locations) in &delegations_in_input {
            let locations = res.entry(trustee.to_owned()).or_insert(HashMap::new());
            for (expected_location, _) in expected_locations {
                locations.entry(expected_location.to_owned()).or_insert((vec![], vec![], vec![]));
            }
        }
        for (trustee, found_locations) in &aces_found {
            let locations = res.entry(trustee.to_owned()).or_insert(HashMap::new());
            for (found_location, _) in found_locations {
                locations.entry(found_location.to_owned()).or_insert((vec![], vec![], vec![]));
            }
        }

        let empty_default1 = HashMap::new();
        let empty_default2 = HashMap::new();
        let empty_default3 = Vec::new();
        let empty_default4 = Vec::new();
        for (trustee, locations) in &mut res {
            let found_locations = aces_found.get(trustee).unwrap_or(&empty_default1);
            let expected_locations = delegations_in_input.get(trustee).unwrap_or(&empty_default2);
            for (location, (deleg_found, deleg_missing, ace_orphans)) in locations {
                let found_aces = found_locations.get(location).unwrap_or(&empty_default3);
                let expected_delegations  = expected_locations.get(location).unwrap_or(&empty_default4);
                let mut explained_aces = vec![false; found_aces.len()];

                for (expected_delegation, expected_aces) in expected_delegations {
                    if let Some(indexes) = find_ace_positions(expected_aces, found_aces) {
                        for index in indexes {
                            explained_aces[index] = true;
                        }
                        deleg_found.push(expected_delegation.to_owned());
                    } else {
                        deleg_missing.push(expected_delegation.to_owned());
                    }
                }

                for (index, explained) in explained_aces.iter().enumerate() {
                    if *explained {
                        continue;
                    }
                    ace_orphans.push(found_aces[index].clone());
                }
            }
        }

        res
    }

    pub fn describe_ace(&self, ace: &Ace) -> String {
        let mut res = vec![];

        if (ace.access_mask & ADS_RIGHT_WRITE_DAC.0 as u32) != 0 {
            res.push("Add/delete delegations".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_WRITE_DAC.0 as u32) != 0 {
            res.push("Change the owner".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32) != 0 {
            if let Some(guid) = ace.get_object_type() {
                if let Some(name) = self.schema.control_access_names.get(guid) {
                    res.push(capitalize(name));
                } else {
                    res.push("Perform all application-specific operations".to_owned());
                }
            }
            else {
                res.push("Perform all application-specific operations".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_SELF.0 as u32) != 0 {
            if let Some(guid) = ace.get_object_type() {
                if let Some(name) = self.schema.validated_write_names.get(guid) {
                    res.push(capitalize(name));
                } else {
                    res.push("Perform all validated writes".to_owned());
                }
            }
            else {
                res.push("Perform all validated writes".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_ACCESS_SYSTEM_SECURITY.0 as u32) != 0 {
            res.push("Add/delete auditing rules".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DELETE.0 as u32) != 0 {
            res.push("Delete".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DELETE.0 as u32) != 0 {
            res.push("Delete along with all children".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DS_CREATE_CHILD.0 as u32) != 0 {
            if let Some(guid) = ace.get_object_type() {
                let mut found = false;
                for (class_name, class_guid) in &self.schema.class_guids {
                    if class_guid == guid {
                        res.push(format!("Create child {} objects", class_name));
                        found = true;
                        break;
                    }
                }
                if !found {
                    res.push("Create child objects of any type".to_owned());
                }
            }
            else {
                res.push("Create child objects of any type".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_DELETE_CHILD.0 as u32) != 0 {
            if let Some(guid) = ace.get_object_type() {
                let mut found = false;
                for (class_name, class_guid) in &self.schema.class_guids {
                    if class_guid == guid {
                        res.push(format!("Delete child {} objects", class_name));
                        found = true;
                        break;
                    }
                }
                if !found {
                    res.push("Delete child objects of any type".to_owned());
                }
            }
            else {
                res.push("Delete child objects of any type".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_WRITE_PROP.0 as u32) != 0 {
            if let Some(guid) = ace.get_object_type() {
                if let Some(name) = self.schema.attribute_guids.get(guid) {
                    res.push(format!("Write attribute {}", name));
                }
                else if let Some(name) = self.schema.property_set_names.get(guid) {
                    res.push(format!("Write attributes of category {}", name));
                }
                else {
                    res.push("Write all properties".to_owned());
                }
            } else {
                res.push("Write all properties".to_owned());
            }
        }
        
        let mut res = res.join(", ");
        if ace.get_container_inherit() {
            if ace.get_inherit_only() {
                res.push_str(" on all child objects");
            } else {
                res.push_str(" on all child objects and the container itself");
            }
        }
        res
    }

    pub fn resolve_sid(&self, sid: &Sid) -> String {
        let base = format!("<SID={}>", sid);
        let search = LdapSearch::new(&self.ldap, Some(&base), LDAP_SCOPE_BASE, Some("(objectClass=*)"), Some(&["objectClass"]), &[]);
        if let Ok(mut res) = search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
            if let Some(entry) = res.pop() {
                let classes = get_attr_strs(&[&entry], &base, "objectclass").expect("unable to fetch objectClass");
                return entry.dn.clone();
            }
        }
        sid.to_string()
    }

    pub fn resolve_str_to_sid(&self, trustee: &str) -> Option<Sid> {
        if let Some((netbios_name,username)) = trustee.split_once("\\") {
            for domain in &self.domains {
                if domain.netbios_name.to_lowercase() == netbios_name.to_lowercase() {
                    let search = LdapSearch::new(&self.ldap, Some(&domain.distinguished_name), LDAP_SCOPE_SUBTREE, Some(&format!("(samAccountName={})", username)), Some(&["objectSid"]), &[]);
                    if let Ok(res) = search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
                        if let Ok(sid) = get_attr_sid(&res, &domain.distinguished_name, "objectsid") {
                            return Some(sid);
                        }
                    }
                }
            }
            return None;
        }
        for domain in &self.domains {
            if ends_with_case_insensitive(trustee, &domain.distinguished_name) {
                let search = LdapSearch::new(&self.ldap, Some(&trustee), LDAP_SCOPE_BASE, None, Some(&["objectSid"]), &[]);
                return match search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
                    Ok(res) => get_attr_sid(&res, &trustee, "objectsid").map(|sid| Some(sid)).unwrap_or(None),
                    _ => None,
                };
            }
        }
        if let Ok(sid) = Sid::try_from(trustee) {
            return Some(sid);
        }
        None
    }
}

fn ace_equivalent(a: &Ace, b: &Ace) -> bool {
    if a == b {
        return true;
    }

    let mut a = a.clone();
    let mut b = b.clone();

    a.access_mask = a.access_mask & !(crate::delegations::IGNORED_ACCESS_RIGHTS);
    b.access_mask = b.access_mask & !(crate::delegations::IGNORED_ACCESS_RIGHTS);

    a == b
}

fn find_ace_positions(needle: &[Ace], haystack: &[Ace]) -> Option<Vec<usize>> {
    let mut res = vec![];
    let mut iter = haystack.iter().enumerate();
    for needle_ace in needle {
        let mut found = false;
        while let Some((haystack_pos, haystack_ace)) = iter.next() {
            if ace_equivalent(haystack_ace, needle_ace) {
                res.push(haystack_pos);
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
    }
    Some(res)
}