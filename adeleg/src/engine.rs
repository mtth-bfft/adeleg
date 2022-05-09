use winldap::connection::LdapConnection;
use std::collections::{HashMap, HashSet};
use crate::delegations::{Delegation, DelegationTemplate, DelegationLocation, get_explicit_aces, get_schema_aces};
use crate::utils::{Domain, get_domains, get_adminsdholder_aces};
use crate::schema::Schema;
use authz::{Sid, Ace};

pub(crate) struct Engine<'a> {
    ldap: &'a LdapConnection,
    domains: &'a [Domain],
    root_domain: &'a Domain,
    schema: &'a Schema,
    pub(crate) templates: HashMap<String, DelegationTemplate>,
    delegations: Vec<Delegation>,
}

impl<'a> Engine<'a> {
    pub fn new(ldap: &'a LdapConnection, domains: &'a [Domain], root_domain: &'a Domain, schema: &'a Schema) -> Self {
        Self {
            ldap,
            domains,
            root_domain,
            schema,
            templates: HashMap::new(),
            delegations: Vec::new(),
        }
    }

    pub fn register_template(&mut self, template: DelegationTemplate) {
        self.templates.insert(template.name.to_owned(), template);
    }

    pub fn register_delegation(&mut self, delegation: Delegation) {
        self.delegations.push(delegation);
    }

    pub fn fetch_aces(&self) -> HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> {
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
        for domain in self.domains.iter() {
            ignored_trustee_sids.insert(domain.sid.with_rid(512));   // Domain Admins
            ignored_trustee_sids.insert(domain.sid.with_rid(516));   // Domain Controllers
            ignored_trustee_sids.insert(domain.sid.with_rid(518));   // Schema Admins
            ignored_trustee_sids.insert(domain.sid.with_rid(519));   // Enterprise Admins
        }

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

        let mut aces_found: HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> = get_schema_aces(&self.schema, &self.root_domain.sid, &ignored_trustee_sids);
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
            match get_explicit_aces(&self.ldap, &naming_context, &self.root_domain.sid, &self.schema, &adminsdholder_aces[..], &ignored_trustee_sids) {
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

        aces_found
    }
}