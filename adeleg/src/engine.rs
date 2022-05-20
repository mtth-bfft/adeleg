use std::collections::{HashMap, HashSet};
use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_WRITE_DAC, ADS_RIGHT_READ_CONTROL, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_DELETE, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_CREATE_CHILD, ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_WRITE_OWNER};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION};
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_BASE, LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID};
use authz::{SecurityDescriptor, Sid, Ace};
use winldap::connection::LdapConnection;
use winldap::utils::{get_attr_strs, get_attr_str};
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use winldap::control::{BerVal, BerEncodable, LdapControl};
use crate::delegations::{Delegation, DelegationTemplate, DelegationLocation};
use crate::error::AdelegError;
use crate::utils::{Domain, find_ace_positions, get_ace_derived_by_inheritance_from_schema, get_domains, get_attr_sid, get_attr_sd, ends_with_case_insensitive, capitalize};
use crate::schema::Schema;

pub const IGNORED_ACCESS_RIGHTS: u32 = (ADS_RIGHT_READ_CONTROL.0 |
    ADS_RIGHT_ACTRL_DS_LIST.0 |
    ADS_RIGHT_DS_LIST_OBJECT.0 |
    ADS_RIGHT_DS_READ_PROP.0) as u32;

pub const IGNORED_CONTROL_ACCESSES: &[&str] = &[
    "apply group policy", // applying a group policy does not mean we control it
    "send to", // sending email to people does not mean we control them
    "change password", // changing password requires knowing the current password, and if you know the password you control the user
    "query self quota", // if an attacker can impersonate a user, querying their quota is the least of their worries
    "open address list", // listing address books is not a control path
    "allow a dc to create a clone of itself", // if an attacker can impersonate a DC, cloning to a new DC is the least of your worries
    "enumerate entire sam domain", // user enumeration is allowed to everyone by default
];

pub(crate) struct Engine<'a> {
    ldap: &'a LdapConnection,
    pub(crate) domains: Vec<Domain>,
    root_domain: Domain,
    schema: Schema,
    ignored_trustee_sids: HashSet<Sid>,
    pub(crate) naming_contexts: Vec<String>,
    resolve_names: bool,
    pub(crate) templates: HashMap<String, DelegationTemplate>,
    pub(crate) delegations: Vec<Delegation>,
}

#[derive(Debug, Clone)]
pub struct AdelegResult {
    pub(crate) non_canonical_ace: Option<Ace>,
    pub(crate) orphan_aces: Vec<Ace>,
    pub(crate) delegations_found: Vec<(Delegation, Sid, Vec<Ace>)>,
    pub(crate) delegations_missing: Vec<(Delegation, Sid)>,
}

impl<'a> Engine<'a> {
    pub fn new(ldap: &'a LdapConnection, resolve_names: bool) -> Self {
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
    
        let schema = match Schema::query(&ldap) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Unable to fetch required information from schema: {}", e);
                std::process::exit(1);
            }
        };

        // Derive a list of trustees to ignore
        let mut ignored_trustee_sids: HashSet<Sid> = HashSet::from([
            Sid::try_from("S-1-5-10").expect("invalid SID"),     // SELF
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
            naming_contexts: ldap.get_naming_contexts().to_vec(),
            ignored_trustee_sids,
            resolve_names,
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

    // Result is indexed by (domain SID) -> (class name) -> (list of ACEs, with a trustee in each)
    fn get_schema_aces(&self) -> Result<HashMap<Sid, HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>>, LdapError> {
        let mut res: HashMap<Sid, HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>> = HashMap::new();

        let search = LdapSearch::new(&self.ldap, Some(self.ldap.get_schema_naming_context()), LDAP_SCOPE_SUBTREE,
            Some("(objectClass=classSchema)"),
            Some(&[
                "lDAPDisplayName",
                "defaultSecurityDescriptor"
            ]), &[]);

        for entry in search {
            let entry = entry?;
            let class_name = get_attr_str(&[&entry], &entry.dn, "ldapdisplayname")?;
            for domain in &self.domains {
                let res = res.entry(domain.sid.clone()).or_default().entry(DelegationLocation::DefaultSecurityDescriptor(class_name.clone()));
                let sddl = match get_attr_str(&[&entry], &entry.dn, "defaultsecuritydescriptor") {
                    Ok(sddl) => sddl,
                    // Not all classes have a default SDDL attribute (if they are not used as the most specialized class of any object)
                    Err(LdapError::RequiredAttributeMissing { .. }) => continue,
                    Err(e) => {
                        res.or_insert(Err(AdelegError::LdapQueryFailed(e)));
                        continue;
                    },
                };
                let sd = match SecurityDescriptor::from_str(&sddl, &domain.sid, &self.root_domain.sid) {
                    Ok(sd) => sd,
                    Err(e) => {
                        res.or_insert(Err(AdelegError::UnableToParseDefaultSecurityDescriptor(e)));
                        continue;
                    },
                };
                let dacl = match sd.dacl {
                    Some(acl) => acl,
                    None => continue,
                };
                let mut entry = AdelegResult {
                    orphan_aces: vec![],
                    non_canonical_ace: dacl.check_canonicality().err(),
                    delegations_found: vec![],
                    delegations_missing: vec![],
                };
                for ace in dacl.aces {
                    if !self.is_ace_interesting(&ace, false, &[]) {
                        continue;
                    }

                    // gMSA are hardcoded by design to not have their password reset, it is not a delegation.
                    if class_name == "msDS-GroupManagedServiceAccount" && !ace.grants_access() && ace.access_mask == ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32 {
                        continue;
                    }

                    entry.orphan_aces.push(ace);
                }
                if !entry.orphan_aces.is_empty() {
                    res.or_insert(Ok(entry));
                }
            }
        }
        Ok(res)
    }

    fn get_adminsdholder_aces(&self, naming_context: &str) -> Result<Vec<Ace>, LdapError> {
        let nc_holding_object = &self.domains.iter()
            .find(|dom| dom.distinguished_name == naming_context)
            .unwrap_or(&self.root_domain)
            .distinguished_name;
        let dn = format!("CN=AdminSDHolder,CN=System,{}", nc_holding_object);
        let mut sd_control_val = BerVal::new();
        sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((DACL_SECURITY_INFORMATION.0).into())]));
            let sd_control = LdapControl::new(
            LDAP_SERVER_SD_FLAGS_OID,
            &sd_control_val,
            true)?;
        let search = LdapSearch::new(self.ldap, Some(&dn),LDAP_SCOPE_BASE,
        Some("(objectClass=*)"),
        Some(&["nTSecurityDescriptor"]), &[&sd_control]);
        let res = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
        let sd = get_attr_sd(&res[..],  &dn, "ntsecuritydescriptor")?;
        Ok(sd.dacl.map(|d| d.aces).unwrap_or(vec![]))
    }

    fn get_explicit_aces(&self, naming_context: &str, schema_aces: &HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>) -> Result<HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>, LdapError> {
        let adminsdholder_aces = self.get_adminsdholder_aces(&naming_context)?;
    
        let mut sd_control_val = BerVal::new();
        sd_control_val.append(BerEncodable::Sequence(vec![BerEncodable::Integer((OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0).into())]));
        let sd_control = LdapControl::new(
            LDAP_SERVER_SD_FLAGS_OID,
            &sd_control_val,
            true)?;
        let search = LdapSearch::new(self.ldap, Some(naming_context), LDAP_SCOPE_SUBTREE,
                                 Some("(objectClass=*)"),
                                 Some(&[
            "nTSecurityDescriptor",
            "objectClass",
            "objectSID",
            "adminCount",
        ]), &[&sd_control]);
    
        let mut res: HashMap<DelegationLocation, Result<AdelegResult, AdelegError>> = HashMap::new();
    
        // Keep track of objectSID -> DN while scanning objects, to ignore delegations to a SID on objects under a container with that SID
        let mut object_sids = HashMap::new();
        for entry in search {
            let entry = entry?;
            if let Ok(object_sid) = get_attr_sid(&[&entry], &entry.dn, "objectsid") {
                object_sids.insert(object_sid, entry.dn.to_owned());
            };
            let res = res.entry(DelegationLocation::Dn(entry.dn.clone()));
            let sd = match get_attr_sd(&[&entry], &entry.dn, "ntsecuritydescriptor") {
                Ok(sd) => sd,
                Err(e) => {
                    res.or_insert(Err(AdelegError::LdapQueryFailed(e)));
                    continue;
                },
            };
            let admincount = get_attr_str(&[&entry], &entry.dn, "admincount")
                .unwrap_or("0".to_owned()) != "0";
            let dacl = sd.dacl.expect("assertion failed: object without a DACL!?");

            let mut record = AdelegResult {
                non_canonical_ace: dacl.check_canonicality().err(),
                orphan_aces: vec![],
                delegations_found: vec![],
                delegations_missing: vec![],
            };

            let most_specific_class = get_attr_strs(&[&entry], &entry.dn, "objectclass")?
                .pop()
                .expect("assertion failed: object without an objectClass!?");
            let default_aces = match schema_aces.get(&DelegationLocation::DefaultSecurityDescriptor(most_specific_class.clone())) {
                Some(Ok(AdelegResult { orphan_aces, ..  })) => &orphan_aces[..],
                _ => &[]
            };
            // Derive ACEs from the defaultSecurityDescriptor of the object's class, and see if the ACE is a default.
            // These ACEs are not simply memcpy()ed, they are treated as if the object had inherited them from the schema.
            let owner = sd.owner.as_ref().expect("assertion failed: object without an owner!?");
            let object_type = self.schema.class_guids.get(&most_specific_class).expect("assertion failed: invalid objectClass?!");
            let default_aces = get_ace_derived_by_inheritance_from_schema(default_aces, &owner, object_type, true);
            for ace in dacl.aces {
                // Do not look for the exact list of default ACEs from the schema in the exact same order:
                // if some ACEs have been removed, we still want to treat the others as implicit ones from the schema.
                if default_aces.contains(&ace) {
                    continue;
                }
                if !self.is_ace_interesting(&ace, admincount, &adminsdholder_aces[..]) {
                    continue;
                }
                record.orphan_aces.push(ace);
            }
            res.or_insert(Ok(record));
        }
    
        // Remove any ACE whose trustee is a parent object (parents control their child containers anyway,
        // e.g. computers control their BitLocker recovery information, TPM information, Hyper-V virtual machine objects, etc.)
        for (location, res) in res.iter_mut() {
            if let DelegationLocation::Dn(dn) = location {
                if let Ok(res) = res {
                    res.orphan_aces.retain(|ace| {
                        if let Some(trustee_dn) = object_sids.get(&ace.trustee) {
                            if ends_with_case_insensitive(dn, trustee_dn) {
                                return false;
                            }
                        }
                        true
                    });
                }
            }
        }

        // Only keep nodes for which we have something to say
        res.retain(|_, res| {
            if let Ok(res) = res {
                if res.non_canonical_ace.is_none() && res.orphan_aces.is_empty() && res.delegations_missing.is_empty() && res.delegations_found.is_empty() {
                    return false;
                }
            }
            true
        });

        Ok(res)
    }

    pub fn is_ace_interesting(&self, ace: &Ace, admincount: bool, adminsdholder_aces: &[Ace]) -> bool {
        let everyone = Sid::try_from("S-1-1-0").expect("invalid SID");

        if ace.is_inherited() {
            return false; // ignore inherited ACEs
        }
        let problematic_rights = ace.access_mask & !(IGNORED_ACCESS_RIGHTS);
        if problematic_rights == 0 {
            return false; // ignore read-only ACEs which cannot be abused (e.g. to read LAPS passwords)
        }
        if ace.trustee == everyone && !ace.grants_access() &&
                (ace.access_mask & !(ADS_RIGHT_DELETE.0 as u32 | ADS_RIGHT_DS_DELETE_CHILD.0 as u32 | ADS_RIGHT_DS_DELETE_TREE.0 as u32)) == 0 {
            return false; // ignore "delete protection" ACEs
        }
        if admincount && adminsdholder_aces.contains(&ace) {
            return false; // ignore ACEs from SDProp on objects marked with adminCount=1 (note: ACEs from
            // AdminSDHolder are not inherited, just copied, so comparison here is a simple fast hash
            // lookup.)
        }
        if self.ignored_trustee_sids.contains(&ace.trustee) {
            return false; // these principals are already in control of the resource (either because they
            // are the resource itself, or because they are highly privileged over the entire forest)
        }
        // Some control accesses do not grant any right on the resource itself, they are not a delegation
        if problematic_rights == ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32 {
            if let Some(guid) = ace.get_object_type() {
                if let Some(name) = self.schema.control_access_names.get(guid) {
                    if IGNORED_CONTROL_ACCESSES.contains(&name.to_lowercase().as_str()) {
                        return false;
                    }
                }
            }
        }

        true
    }


    // Results are indexed by location (DN, class name) -> (orphan ACEs, delegations missing, delegations in place)
    pub fn run(&self) -> Result<HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>, LdapError> {
        // Derive expected ACEs from these delegations, and index these ACEs by Sid then Location
        let mut expected_delegations: HashMap<Sid, HashMap<DelegationLocation, Vec<(Delegation, Vec<Ace>)>>> = HashMap::new();
        for delegation in &self.delegations {
            let expected_aces = match delegation.derive_aces(&self.ldap, &self.root_domain, &self.domains) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!(" [!] Unable to compute expected ACEs from delegation: {}", e);
                    std::process::exit(1);
                    // TODO: move this possibly-error-generating computation (only unresolved samaccountnames, for now)
                    // to the moment a delegation is added, so that the computation is only done once, and the error context
                    // is clearer (JSON file path, line, etc.)
                }
            };
            for (location, aces) in expected_aces {
                let sid = aces.get(0).expect("delegations should have at least one ACE").trustee.clone();
                expected_delegations.entry(sid).or_insert(HashMap::new())
                    .entry(location).or_insert(vec![])
                    .push((delegation.clone(), aces));
            }
        }

        // Fetch all meaningful ACEs
        let schema_aces = self.get_schema_aces()?;
        let mut res = schema_aces.get(&self.root_domain.sid).cloned().unwrap_or_default();
        let mut naming_contexts = Vec::from(self.ldap.get_naming_contexts());
        naming_contexts.sort();

        for naming_context in naming_contexts {
            let domain_sid = &self.domains.iter().find(|d| d.distinguished_name == naming_context)
                .map(|d| &d.sid)
                .unwrap_or(&self.root_domain.sid);
            let schema_aces = schema_aces.get(domain_sid).expect("naming context without an associated domain");

            println!("Fetching security descriptors of naming context {}", naming_context);
            let explicit_aces = self.get_explicit_aces(&naming_context, schema_aces)?;
            res.extend(explicit_aces);
        }

        // Move ACEs from "orphan" to "delegations found" if they match an expected delegation
        // Otherwise let them there, and add the delegation as "missing"
        for (trustee, expected_locations) in &expected_delegations {
            for (location, delegations) in expected_locations {
                for (expected_delegation, expected_aces) in delegations {
                    let res = match res.get_mut(location) {
                        Some(Ok(res)) => res,
                        Some(Err(_)) => continue, // scanning that location failed, don't flag the delegation as "missing"
                        None => continue, // delegation is for an object outside of our scope, ignore it
                    };

                    let mut explained_aces = vec![false; res.orphan_aces.len()];
                    if let Some(indexes) = find_ace_positions(expected_aces, &res.orphan_aces) {
                        let mut matched_aces = vec![];
                        for index in indexes {
                            explained_aces[index] = true;
                            matched_aces.push(res.orphan_aces[index].clone());
                        }
                        res.delegations_found.push((expected_delegation.to_owned(), trustee.clone(), matched_aces));
                    } else {
                        res.delegations_missing.push((expected_delegation.to_owned(), trustee.clone()));
                    }

                    res.orphan_aces = res.orphan_aces.drain(..).enumerate().filter(|(idx, ace)| !explained_aces[*idx]).map(|(idx, ace)| ace).collect();
                }
            }
        }

        Ok(res)
    }

    // Describe this ACE access rights as a string, without mentionning the trustee or the location
    pub fn describe_ace(&self, ace: &Ace) -> String {
        let mut res = vec![];

        if !self.resolve_names && (ace.access_mask & ADS_RIGHT_DS_READ_PROP.0 as u32) != 0 {
            res.push("READ_PROP".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DS_WRITE_PROP.0 as u32) != 0 {
            if self.resolve_names {
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
            } else {
                res.push("WRITE_PROP".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32) != 0 {
            if self.resolve_names {
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
            } else {
                res.push("CONTROL_ACCESS".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_CREATE_CHILD.0 as u32) != 0 {
            if self.resolve_names {
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
            } else {
                res.push("CREATE_CHILD".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_DS_DELETE_CHILD.0 as u32) != 0 {
            if self.resolve_names {
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
            } else {
                res.push("DELETE_CHILD".to_owned());
            }
        }
        if !self.resolve_names && (ace.access_mask & ADS_RIGHT_ACTRL_DS_LIST.0 as u32) != 0 {
            res.push("LIST_CHILDREN".to_owned());
        }
        if !self.resolve_names && (ace.access_mask & ADS_RIGHT_DS_LIST_OBJECT.0 as u32) != 0 {
            res.push("LIST_OBJECT".to_owned());
        }
        if !self.resolve_names && (ace.access_mask & ADS_RIGHT_READ_CONTROL.0 as u32) != 0 {
            res.push("READ_CONTROL".to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_WRITE_OWNER.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Change the owner"
            } else {
                "WRITE_OWNER"
            }.to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_WRITE_DAC.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Add/delete delegations"
            } else {
                "WRITE_DAC"
            }.to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DELETE.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Delete"
            } else {
                "DELETE"
            }.to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DS_DELETE_TREE.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Delete along with all children"
            } else {
                "DELETE_TREE"
            }.to_owned());
        }
        if (ace.access_mask & ADS_RIGHT_DS_SELF.0 as u32) != 0 {
            if self.resolve_names {
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
            } else {
                res.push("VALIDATED_WRITE/SELF".to_owned());
            }
        }
        if (ace.access_mask & ADS_RIGHT_ACCESS_SYSTEM_SECURITY.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Add/delete auditing rules"
            } else {
                "ACCESS_SYSTEM_SECURITY"
            }.to_owned());
        }

        let mut res = res.join(", ");
        if self.resolve_names {
            if ace.get_container_inherit() {
                let mut found = false;
                if let Some(guid) = ace.get_inherited_object_type() {
                    for (class_name, class_guid) in &self.schema.class_guids {
                        if class_guid == guid {
                            res.push_str(&format!(" on all {} child objects", class_name));
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    res.push_str(" on all child objects");
                }
    
                if !ace.get_inherit_only() {
                    res.push_str(" and the container itself");
                }
            }
        } else {
            res.push_str(&format!(" (0x{:X})", ace.access_mask));
            if let Some(guid) = ace.get_object_type() {
                res.push_str(&format!(" OBJECT_GUID={}", guid));
                let mut found = false;
                for (class_name, class_guid) in &self.schema.class_guids {
                    if class_guid == guid {
                        res.push_str(&format!("(class {})", class_name));
                        found = true;
                        break;
                    }
                }
                if !found {
                    for (attr_guid, attr_name) in &self.schema.attribute_guids {
                        if attr_guid == guid {
                            res.push_str(&format!("(attribute {})", attr_name));
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    for (ctrl_guid, ctrl_name) in &self.schema.control_access_names {
                        if ctrl_guid == guid {
                            res.push_str(&format!("(control access {})", ctrl_name));
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    for (attr_guid, attr_name) in &self.schema.property_set_names {
                        if attr_guid == guid {
                            res.push_str(&format!("(property set {})", attr_name));
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    for (ctrl_guid, ctrl_name) in &self.schema.validated_write_names {
                        if ctrl_guid == guid {
                            res.push_str(&format!("(validated write {})", ctrl_name));
                            found = true;
                            break;
                        }
                    }
                }
            }
            if let Some(guid) = ace.get_inherited_object_type() {
                res.push_str(&format!(" INHERIT_OBJECT_TYPE={}", guid));
                for (class_name, class_guid) in &self.schema.class_guids {
                    if class_guid == guid {
                        res.push_str(&format!("(class {})", class_name));
                        break;
                    }
                }
            }
            if ace.get_container_inherit() {
                res.push_str(" [CONTAINER_INHERIT]");
            }
            if ace.get_inherit_only() {
                res.push_str(" [INHERIT_ONLY]");
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
