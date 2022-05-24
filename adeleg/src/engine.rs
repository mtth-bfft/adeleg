use core::fmt::Display;
use core::cell::RefCell;
use std::collections::{HashMap, HashSet};
use windows::Win32::Networking::ActiveDirectory::{ADS_RIGHT_WRITE_DAC, ADS_RIGHT_READ_CONTROL, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_ACCESS_SYSTEM_SECURITY, ADS_RIGHT_DELETE, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_CREATE_CHILD, ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_WRITE_OWNER};
use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SidTypeUser, SidTypeGroup, SidTypeComputer};
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_BASE, LDAP_SCOPE_SUBTREE, LDAP_SERVER_SD_FLAGS_OID};
use windows::Win32::Security::SID_NAME_USE;
use windows::Win32::Foundation::{PSID, PSTR, PWSTR, BOOL};
use authz::{SecurityDescriptor, Sid, Ace};
use windows::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use windows::Win32::System::SystemServices::SE_DACL_PROTECTED;
use winldap::connection::LdapConnection;
use winldap::utils::{get_attr_strs, get_attr_str};
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use winldap::control::{BerVal, BerEncodable, LdapControl};
use crate::delegations::{Delegation, DelegationTemplate, DelegationLocation, DelegationRights};
use crate::error::AdelegError;
use crate::utils::{Domain, find_ace_positions, get_ace_derived_by_inheritance_from_schema, get_domains, get_attr_sid, get_attr_sd, ends_with_case_insensitive, capitalize};
use crate::schema::Schema;
use authz::Guid;

pub const BUILTIN_ACES: &str = include_str!("..\\builtin_delegations.json");

pub const IGNORED_ACCESS_RIGHTS: u32 = (ADS_RIGHT_READ_CONTROL.0 |
    ADS_RIGHT_ACTRL_DS_LIST.0 |
    ADS_RIGHT_DS_LIST_OBJECT.0 |
    ADS_RIGHT_DS_READ_PROP.0) as u32;

pub const IGNORED_CONTROL_ACCESSES: &[&str] = &[
    "apply group policy", // applying a group policy does not mean we control it
    "allow a dc to create a clone of itself", // if an attacker can impersonate a DC, cloning to a new DC is the least of your worries
];

pub const IGNORED_BLOCK_DACL_CLASSES: &[&str] = &[
    "grouppolicycontainer", // GPOs block inheritance by design, due to the way Group Policy Creator Owner is delegated
];

pub const IGNORED_BLOCK_DACL_DOMAIN_CONTAINERS: &[&str] = &[
    "CN=AdminSDHolder,CN=System", // AdminSDHolder, for SDProp to protect administrators
    "CN=WMIPolicy,CN=System", // by design, due to the way Group Policy Creator Owner is delegated
    "CN=SOM,CN=WMIPolicy,CN=System", // by design, due to the way Group Policy Creator Owner is delegated
];

#[derive(Debug, Clone)]
pub enum PrincipalType {
    User,
    Group,
    Computer,
    External,
}

impl Display for PrincipalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalType::User => f.write_str("User"),
            PrincipalType::Group => f.write_str("Group"),
            PrincipalType::Computer => f.write_str("Computer"),
            PrincipalType::External => f.write_str("External"),
        }
    }
}

impl From<SID_NAME_USE> for PrincipalType {
    fn from(siduse: SID_NAME_USE) -> Self {
        if siduse == SidTypeUser {
            PrincipalType::User
        } else if siduse == SidTypeGroup {
            PrincipalType::Group
        } else if siduse == SidTypeComputer {
            PrincipalType::Computer
        } else {
            PrincipalType::External
        }
    }
}

impl From<&str> for PrincipalType {
    fn from(most_specific_class: &str) -> Self {
        let most_specific_class = most_specific_class.to_ascii_lowercase();
        if most_specific_class == "computer" {
            PrincipalType::Computer
        } else if most_specific_class == "user" {
            PrincipalType::User
        } else if most_specific_class == "group" {
            PrincipalType::Group
        } else {
            PrincipalType::External
        }
    }
}

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
    expected_aces: HashMap<Sid, HashMap<DelegationLocation, Vec<(Delegation, Vec<Ace>)>>>,
    resolved_sid_to_dn: RefCell<HashMap<Sid, String>>,
    resolved_sid_to_type: RefCell<HashMap<Sid, PrincipalType>>,
    p_lookupaccountsidlocal: Option<unsafe extern "system" fn(PSID, PWSTR, *mut u32, PWSTR, *mut u32, *mut SID_NAME_USE) -> BOOL>,
}

#[derive(Debug, Clone)]
pub struct AdelegResult {
    pub(crate) dacl_protected: bool,
    pub(crate) owner: Option<Sid>,
    pub(crate) non_canonical_ace: Option<Ace>,
    pub(crate) deleted_trustee: Vec<Ace>,
    pub(crate) orphan_aces: Vec<Ace>,
    pub(crate) delegations_found: Vec<(Delegation, Sid, Vec<Ace>)>,
    pub(crate) delegations_missing: Vec<(Delegation, Sid)>,
}

impl AdelegResult {
    pub(crate) fn needs_to_be_displayed(&self, view_builtin_delegations: bool) -> bool {
        self.dacl_protected ||
            self.owner.is_some() ||
            self.non_canonical_ace.is_some() ||
            !self.deleted_trustee.is_empty() ||
            !self.orphan_aces.is_empty() ||
            self.delegations_found.iter().any(|(d, _, _)| !d.builtin) ||
            (!self.delegations_found.is_empty() && view_builtin_delegations) ||
            !self.delegations_missing.is_empty()
    }
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

        let h_sechost = unsafe { LoadLibraryA(PSTR(b"sechost.dll\x00".as_ptr())) };
        let p_lookupaccountsidlocal: Option<unsafe extern "system" fn(PSID, PWSTR, *mut u32, PWSTR, *mut u32, *mut SID_NAME_USE) -> BOOL> = if h_sechost.is_invalid() {
            None
        } else {
            unsafe { GetProcAddress(h_sechost, PSTR(b"LookupAccountSidLocalW\x00".as_ptr())).map(|f| core::mem::transmute(f)) }
        };

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
            expected_aces: HashMap::new(),
            p_lookupaccountsidlocal,
            resolved_sid_to_dn: RefCell::new(HashMap::new()),
            resolved_sid_to_type: RefCell::new(HashMap::new()),
        }
    }

    pub fn load_template_json(&mut self, json: &str) -> Result<(), AdelegError> {
        let json = json.trim();
        if json.is_empty() {
            return Ok(()); // empty file are invalid JSON, just skip them
        }
        let templates = DelegationTemplate::from_json(&json, &self.schema)?;
        for template in templates.into_iter() {
            self.templates.insert(template.name.to_owned(), template);
        }
        Ok(())
    }

    pub fn load_delegation_json(&mut self, json: &str) -> Result<(), AdelegError> {
        let json = json.trim();
        if json.is_empty() {
            return Ok(()); // empty file are invalid JSON, just skip them
        }
        // Derive expected ACEs from these delegations, and index these ACEs by Sid then Location
        let mut delegations = Delegation::from_json(&json, &self.templates, &self.schema)?;
        for delegation in &delegations {
            let expected_aces = delegation.derive_aces(&self.ldap, &self.root_domain, &self.domains)?;
            for (location, aces) in expected_aces {
                if let Some(first_ace) = aces.get(0) {
                    let sid = first_ace.trustee.clone();
                    self.expected_aces.entry(sid).or_insert(HashMap::new())
                        .entry(location).or_insert(vec![])
                        .push((delegation.clone(), aces));
                }
            }
        }
        self.delegations.append(&mut delegations);
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
                let dacl_protected = (sd.controls as u32 & SE_DACL_PROTECTED) != 0 &&
                    !IGNORED_BLOCK_DACL_CLASSES.contains(&class_name.to_ascii_lowercase().as_str());
                let dacl = match sd.dacl {
                    Some(acl) => acl,
                    None => continue,
                };
                let mut entry = AdelegResult {
                    dacl_protected,
                    owner: None,
                    deleted_trustee: vec![],
                    orphan_aces: vec![],
                    non_canonical_ace: dacl.check_canonicality().err(),
                    delegations_found: vec![],
                    delegations_missing: vec![],
                };
                for ace in dacl.aces {
                    if !self.is_ace_interesting(&ace, false, &[]) {
                        continue;
                    }
                    entry.orphan_aces.push(ace);
                }
                if entry.needs_to_be_displayed(true) {
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
        for entry in search {
            let entry = entry?;
            let res = res.entry(DelegationLocation::Dn(entry.dn.clone()));
            let sd = match get_attr_sd(&[&entry], &entry.dn, "ntsecuritydescriptor") {
                Ok(sd) => sd,
                Err(e) => {
                    res.or_insert(Err(AdelegError::LdapQueryFailed(e)));
                    continue;
                },
            };
            let most_specific_class = match get_attr_strs(&[&entry], &entry.dn, "objectclass") {
                Ok(mut v) => v.pop().expect("assertion failed: object with an empty objectClass!?").to_ascii_lowercase(),
                Err(e) => {
                    res.or_insert(Err(AdelegError::LdapQueryFailed(e)));
                    continue;
                }
            };
            if let Ok(object_sid) = get_attr_sid(&[&entry], &entry.dn, "objectsid") {
                // Some well-known SIDs will be found this way, in CN=ForeignSecurityPrincipals in each domain.
                // We prefer these SIDs to be shown as a resolved entry (in a "Global" section), so we first try to look them
                // up (using LookupAccountSidLocal()) and only use their DN if that fails.
                if object_sid.is_domain_specific() || self.resolve_sid(&object_sid).is_none() {
                    self.resolved_sid_to_dn.borrow_mut().insert(object_sid.clone(), entry.dn.clone());
                    self.resolved_sid_to_type.borrow_mut().insert(object_sid.clone(), PrincipalType::from(most_specific_class.as_str()));
                }
            }
            let admincount = get_attr_str(&[&entry], &entry.dn, "admincount")
                .unwrap_or("0".to_owned()) != "0";
            let owner = sd.owner.expect("assertion failed: object without an owner!?");
            let dacl = sd.dacl.expect("assertion failed: object without a DACL!?");

            let (default_aces, default_dacl_protected) = match schema_aces.get(&DelegationLocation::DefaultSecurityDescriptor(most_specific_class.clone())) {
                Some(Ok(AdelegResult { dacl_protected, orphan_aces, ..  })) => (&orphan_aces[..], *dacl_protected),
                _ => (&[] as &[Ace], false),
            };
            let dacl_protected = ((sd.controls as u32 & SE_DACL_PROTECTED) != 0) &&
                !default_dacl_protected &&
                !admincount &&
                !IGNORED_BLOCK_DACL_CLASSES.contains(&most_specific_class.to_ascii_lowercase().as_str()) &&
                !IGNORED_BLOCK_DACL_DOMAIN_CONTAINERS.iter().any(|rdn| entry.dn.eq_ignore_ascii_case(&format!("{},{}", rdn, naming_context)));

            // Derive ACEs from the defaultSecurityDescriptor of the object's class, and see if the ACE is a default.
            // These ACEs are not simply memcpy()ed, they are treated as if the object had inherited them from the schema.
            let object_type = self.schema.class_guids.get(&most_specific_class).expect("assertion failed: invalid objectClass?!");
            let default_aces = get_ace_derived_by_inheritance_from_schema(default_aces, &owner, object_type, true);

            let owner = if self.ignored_trustee_sids.contains(&owner) {
                None
            } else {
                Some(owner)
            };
            let mut record = AdelegResult {
                dacl_protected,
                owner,
                non_canonical_ace: dacl.check_canonicality().err(),
                deleted_trustee: vec![],
                orphan_aces: vec![],
                delegations_found: vec![],
                delegations_missing: vec![],
            };

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
            if record.needs_to_be_displayed(true) {
                res.or_insert(Ok(record));
            }
        }

        // Remove any ACE whose trustee is a parent object (parents control their child containers anyway,
        // e.g. computers control their BitLocker recovery information, TPM information, Hyper-V virtual machine objects, etc.)
        for (location, res) in res.iter_mut() {
            if let DelegationLocation::Dn(dn) = location {
                if let Ok(res) = res {
                    res.orphan_aces.retain(|ace| {
                        if let Some(trustee_dn) = self.resolved_sid_to_dn.borrow().get(&ace.trustee) {
                            if ends_with_case_insensitive(dn, trustee_dn) {
                                return false;
                            }
                        }
                        true
                    });
                }
            }
        }
        Ok(res)
    }

    pub fn is_ace_interesting(&self, ace: &Ace, admincount: bool, adminsdholder_aces: &[Ace]) -> bool {
        let everyone = Sid::try_from("S-1-1-0").expect("invalid SID");

        if ace.is_inherited() {
            return false; // ignore inherited ACEs
        }
        let problematic_rights = ace.access_mask & !(IGNORED_ACCESS_RIGHTS);
        if problematic_rights == 0 {
            return false; // ignore read-only ACEs which cannot be abused
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

    // Results are indexed by location (DN or class name) -> (orphan ACEs, delegations missing, delegations in place)
    pub fn run(&self) -> Result<HashMap<DelegationLocation, Result<AdelegResult, AdelegError>>, LdapError> {
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

            let explicit_aces = self.get_explicit_aces(&naming_context, schema_aces)?;
            res.extend(explicit_aces);

            // Move ACEs from "orphan" to "deleted trustee" if the trustee is from this forest and does
            // not exist anymore
            let domain_sid = domain_sid.with_rid(0);
            for (_, result) in res.iter_mut() {
                if let Ok(result) = result {
                    result.orphan_aces.retain(|ace| {
                        if ace.trustee.shares_prefix_with(&domain_sid) && self.resolve_sid(&ace.trustee).is_none() {
                            result.deleted_trustee.push(ace.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }

        // Move ACEs from "orphan" to "delegations found" if they match an expected delegation
        // Otherwise let them there, and add the delegation as "missing"
        for (trustee, expected_locations) in &self.expected_aces {
            for (location, expected_delegations) in expected_locations {
                for (expected_delegation, expected_aces) in expected_delegations {
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
                        if !expected_delegation.builtin {
                            res.delegations_missing.push((expected_delegation.to_owned(), trustee.clone()));
                        }
                    }

                    res.orphan_aces = res.orphan_aces.drain(..).enumerate().filter(|(idx, _)| !explained_aces[*idx]).map(|(_, ace)| ace).collect();
                }
            }
        }

        Ok(res)
    }

    pub fn describe_delegation_rights(&self, delegation_rights: &DelegationRights) -> String {
        match delegation_rights {
            DelegationRights::Ace(ace) => format!("{} {}", if ace.allow { "Allow" } else { "Deny" }, self.describe_ace(
                ace.access_mask,
                ace.object_type.as_ref(),
                ace.inherited_object_type.as_ref(),
                ace.container_inherit,
                ace.inherit_only
            )),
            DelegationRights::TemplateName { template } => template.clone(),
            DelegationRights::Template(template) => template.name.clone(),
        }
    }

    // Describe this ACE access rights as a string, without mentionning the trustee or the location
    pub fn describe_ace(&self, access_mask: u32, object_type: Option<&Guid>, inherit_object_type: Option<&Guid>, container_inherit: bool, inherit_only: bool) -> String {
        let mut res = vec![];

        if !self.resolve_names && (access_mask & ADS_RIGHT_DS_READ_PROP.0 as u32) != 0 {
            res.push("READ_PROP".to_owned());
        }
        if (access_mask & ADS_RIGHT_DS_WRITE_PROP.0 as u32) != 0 {
            if self.resolve_names {
                if let Some(guid) = object_type {
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
        if (access_mask & ADS_RIGHT_DS_CONTROL_ACCESS.0 as u32) != 0 {
            if self.resolve_names {
                if let Some(guid) = object_type {
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
        if (access_mask & ADS_RIGHT_DS_CREATE_CHILD.0 as u32) != 0 {
            if self.resolve_names {
                if let Some(guid) = object_type {
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
        if (access_mask & ADS_RIGHT_DS_DELETE_CHILD.0 as u32) != 0 {
            if self.resolve_names {
                if let Some(guid) = object_type {
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
        if !self.resolve_names && (access_mask & ADS_RIGHT_ACTRL_DS_LIST.0 as u32) != 0 {
            res.push("LIST_CHILDREN".to_owned());
        }
        if !self.resolve_names && (access_mask & ADS_RIGHT_DS_LIST_OBJECT.0 as u32) != 0 {
            res.push("LIST_OBJECT".to_owned());
        }
        if !self.resolve_names && (access_mask & ADS_RIGHT_READ_CONTROL.0 as u32) != 0 {
            res.push("READ_CONTROL".to_owned());
        }
        if (access_mask & ADS_RIGHT_WRITE_OWNER.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Change the owner"
            } else {
                "WRITE_OWNER"
            }.to_owned());
        }
        if (access_mask & ADS_RIGHT_WRITE_DAC.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Add/delete delegations"
            } else {
                "WRITE_DAC"
            }.to_owned());
        }
        if (access_mask & ADS_RIGHT_DELETE.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Delete"
            } else {
                "DELETE"
            }.to_owned());
        }
        if (access_mask & ADS_RIGHT_DS_DELETE_TREE.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Delete along with all children"
            } else {
                "DELETE_TREE"
            }.to_owned());
        }
        if (access_mask & ADS_RIGHT_DS_SELF.0 as u32) != 0 {
            if self.resolve_names {
                if let Some(guid) = object_type {
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
        if (access_mask & ADS_RIGHT_ACCESS_SYSTEM_SECURITY.0 as u32) != 0 {
            res.push(if self.resolve_names {
                "Add/delete auditing rules"
            } else {
                "ACCESS_SYSTEM_SECURITY"
            }.to_owned());
        }

        let mut res = res.join(", ");
        if self.resolve_names {
            if container_inherit {
                let mut found = false;
                if let Some(guid) = inherit_object_type {
                    for (class_name, class_guid) in &self.schema.class_guids {
                        if class_guid == guid {
                            res.push_str(&format!(", on all {} child objects", class_name));
                            found = true;
                            break;
                        }
                    }
                }
                if !found {
                    res.push_str(", on all child objects");
                }
    
                if !inherit_only {
                    res.push_str(" and the container itself");
                }
            }
        } else {
            res.push_str(&format!(" (0x{:X})", access_mask));
            if let Some(guid) = object_type {
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
                            break;
                        }
                    }
                }
            }
            if let Some(guid) = inherit_object_type {
                res.push_str(&format!(" INHERIT_OBJECT_TYPE={}", guid));
                for (class_name, class_guid) in &self.schema.class_guids {
                    if class_guid == guid {
                        res.push_str(&format!("(class {})", class_name));
                        break;
                    }
                }
            }
            if container_inherit {
                res.push_str(" [CONTAINER_INHERIT]");
            }
            if inherit_only {
                res.push_str(" [INHERIT_ONLY]");
            }
        }
        res
    }

    pub fn resolve_sid(&self, sid: &Sid) -> Option<(String, PrincipalType)> {
        if let Some(dn) = self.resolved_sid_to_dn.borrow().get(sid) {
            return Some((dn.clone(), self.resolved_sid_to_type.borrow().get(sid).cloned().unwrap_or(PrincipalType::External)));
        }

        // Try to resolve locally, in case it is a well known SID
        if let Some(p_lookupaccountsidlocal) = self.p_lookupaccountsidlocal {
            let mut siduse = SID_NAME_USE::default();
            let mut user_name = vec![0u16; 256];
            let mut user_name_len = user_name.len() as u32;
            let mut domain_name = vec![0u16; 256];
            let mut domain_name_len = domain_name.len() as u32;

            // LookupAccountSidLocalW from sechost.dll is not in windows-rs (yet)
            let succeeded = unsafe {
                p_lookupaccountsidlocal(PSID(sid.as_bytes().as_ptr() as isize), PWSTR(user_name.as_mut_ptr()), &mut user_name_len as *mut _, PWSTR(domain_name.as_mut_ptr()), &mut domain_name_len as *mut _, &mut siduse as *mut _)
            };
            if succeeded.as_bool() {
                user_name.truncate(user_name_len as usize);
                domain_name.truncate(domain_name_len as usize);
                if !user_name.is_empty() {
                    let name = if domain_name.is_empty() {
                        String::from_utf16_lossy(&user_name)
                    } else {
                        format!("{}\\{}", String::from_utf16_lossy(&domain_name), String::from_utf16_lossy(&user_name))
                    };
                    let ptype = PrincipalType::from(siduse);
                    self.resolved_sid_to_dn.borrow_mut().insert(sid.clone(), name.clone());
                    self.resolved_sid_to_type.borrow_mut().insert(sid.clone(), ptype.clone());
                    return Some((name, ptype));
                }
            }
        }
        
        let base = format!("<SID={}>", sid);
        let search = LdapSearch::new(&self.ldap, Some(&base), LDAP_SCOPE_BASE, Some("(objectClass=*)"), Some(&["objectClass"]), &[]);
        if let Ok(mut res) = search.collect::<Result<Vec<LdapEntry>, LdapError>>() {
            if let Some(entry) = res.pop() {
                if let Ok(mut classes) = get_attr_strs(&[&entry], &base, "objectclass") {
                    let dn = entry.dn;
                    let most_specific_class = classes.pop().expect("assertion failed: object with empty objectClass!?");
                    let ptype = PrincipalType::from(most_specific_class.as_str());
                    self.resolved_sid_to_dn.borrow_mut().insert(sid.clone(), dn.clone());
                    self.resolved_sid_to_type.borrow_mut().insert(sid.clone(), ptype.clone());
                    return Some((dn, ptype));
                }
            }
        }

        None
    }

    pub fn resolve_str_to_sid(&self, trustee: &str) -> Option<Sid> {
        for (sid, name) in self.resolved_sid_to_dn.borrow().iter() {
            if name == trustee {
                return Some(sid.clone());
            }
        }
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
