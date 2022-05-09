//#![windows_subsystem = "windows"]

mod utils;
mod schema;
mod delegations;
mod engine;
mod gui;

use std::collections::{HashMap, HashSet};
use authz::{Ace, Sid};
use delegations::{DelegationLocation, DelegationTemplate};
use utils::resolve_trustee_to_sid;
use winldap::connection::{LdapConnection, LdapCredentials};
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};
use crate::gui::run_gui;
use crate::schema::Schema;
use crate::engine::Engine;
use crate::delegations::{get_explicit_aces, get_schema_aces, Delegation};
use crate::utils::{get_adminsdholder_aces, pretty_print_ace, get_domains};

fn main() {
    run_gui();
    let default_port = format!("{}", LDAP_PORT);
    let app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("server")
                .help("(explicit server) LDAP server hostname or IP")
                .long("server")
                .short('s')
                .number_of_values(1)
        )
        .arg(
            Arg::new("port")
                .help("(explicit server) LDAP port")
                .long("port")
                .number_of_values(1)
                .default_value(&default_port)
        )
        .arg(
            Arg::new("domain")
                .help("(explicit credentials) Logon domain name")
                .long("domain")
                .short('d')
                .number_of_values(1)
                .requires_all(&["username", "password"])
        )
        .arg(
            Arg::new("username")
                .help("(explicit credentials) Logon user name")
                .long("user")
                .short('u')
                .number_of_values(1)
                .requires_all(&["domain","password"])
        )
        .arg(
            Arg::new("password")
                .help("(explicit credentials) Logon Password")
                .long("password")
                .short('p')
                .number_of_values(1)
                .requires_all(&["domain","username"])
        )
        .arg(
            Arg::new("templates")
                .help("json file with delegation templates")
                .long("templates")
                .short('t')
                .value_name("T.json")
                .multiple_occurrences(true)
                .number_of_values(1)
        )
        .arg(
            Arg::new("delegations")
                .help("json file with delegations")
                .long("delegations")
                .short('D')
                .value_name("D.json")
                .multiple_occurrences(true)
                .number_of_values(1)
        ).arg(
            Arg::new("trustee")
                .help("only show delegations granted to this trustee")
                .long("trustee")
                .value_name("SID|samaccountname|DN")
                .number_of_values(1)
        );

    let args = app.get_matches();

    let server= args.value_of("server");
    let port = args.value_of("port").expect("no port set");
    let port = match port.parse::<u16>() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("Unable to parse \"{}\" as TCP port", port);
            std::process::exit(1);
        }
    };
    let credentials = match (args.value_of("domain"),
                             args.value_of("username"),
                             args.value_of("password")) {
        (Some(d), Some(u), Some(p)) => {
            Some(LdapCredentials {
                domain: d,
                username: u,
                password: p,
            })
        },
        _ => None,
    };

    let conn = match LdapConnection::new(server, port, credentials.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Unable to connect to \"{}:{}\" : {}", server.unwrap_or("default"), port, e);
            std::process::exit(1);
        }
    };

    let domains = match get_domains(&conn) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Unable to list domains: {}", e);
            std::process::exit(1);
        }
    };

    let root_domain = {
        let root_nc = conn.get_root_domain_naming_context();
        let mut res = None;
        for domain in &domains {
            if domain.distinguished_name == root_nc {
                res = Some(domain);
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
    let schema = match Schema::query(&conn, &domain_sids[..], &root_domain.sid) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to fetch required information from schema: {}", e);
            std::process::exit(1);
        }
    };

    let mut engine = Engine::new(&conn, &domains, root_domain, &schema);

    if let Some(input_filepaths) = args.values_of("templates") {
        for input_filepath in input_filepaths.into_iter() {
            let json = match std::fs::read_to_string(input_filepath) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(" [!] Unable to open file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            };
            match DelegationTemplate::from_json(&json, &schema) {
                Ok(v) => {
                    for template in v.into_iter() {
                        engine.register_template(template);
                    }
                },
                Err(e) => {
                    eprintln!(" [!] Unable to parse template file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            }
        }
    }

    if let Some(input_files) = args.values_of("delegations") {
        for input_filepath in input_files.into_iter() {
            let json = match std::fs::read_to_string(input_filepath) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(" [!] Unable to open file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            };
            let delegations = match Delegation::from_json(&json, &engine.templates) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(" [!] Unable to parse delegation file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            };
            for delegation in delegations.into_iter() {
                engine.register_delegation(delegation);
            }
        }
    }

    let mut aces_found = engine.fetch_aces();

    if let Some(trustee) = args.value_of("trustee") {
        let sid = match resolve_trustee_to_sid(trustee, &conn, &domains) {
            Some(sid) => sid,
            None => {
                eprintln!("Error: Could not resolve trustee \"{}\" (valid syntaxes are SIDs (S-1-5-21-*), distinguished names, and NetbiosName\\samAccountName)", trustee);
                std::process::exit(1);
            },
        };
        let res = aces_found.get(&sid).cloned().unwrap_or_default();
        aces_found.clear();
        aces_found.insert(sid, res.to_owned());
    }

    if let Err(e) = conn.destroy() {
        eprintln!("Error when closing connection to \"{}:{}\" : {}", server.unwrap_or(""), port, e);
        std::process::exit(1);
    }

    /*for (trustee, locations) in &aces_found {
        for (location, aces) in locations {
            // Check if the expected delegations are in place, while keeping track of which ACEs are explained
            // by >= 1 delegation (so that, at the end, we can say which ACEs are not covered by a known delegation)
            let mut aces_explained: Vec<(&Ace, bool)> = aces.iter().map(|ace| (ace, false)).collect();

            let expected_delegations = delegations_in_input.get(trustee)
                .and_then(|h| h.get(&location).map(|v| v.as_slice()))
                .unwrap_or(&[]);
            for (_, expected_aces) in expected_delegations {
                if let Some(positions) = find_ace_positions(&expected_aces, &aces[..]) {
                    for pos in positions {
                        aces_explained[pos].1 = true;
                    }
                }
            }

            if aces_explained.iter().any(|(_, explained)| !*explained) {
                println!("====== Considering {} on {:?}", &trustee, &location);

                eprintln!(" [.] Expected ACEs:");
                for (delegation, aces) in expected_delegations {
                    for ace in aces {
                        eprintln!("          {:?} (from template \"{}\")", pretty_print_ace(ace, &schema), delegation.template_name);
                    }
                }

                eprintln!(" [.] ACEs found:");
                for (ace, explained) in aces_explained {
                    eprintln!("          {} {}", if explained { "[OK]" } else { "[!!]" }, pretty_print_ace(ace, &schema));
                }

                eprintln!("");
            }
        }
    }*/
}

fn ace_equivalent(a: &Ace, b: &Ace) -> bool {
    if a == b {
        return true;
    }

    let mut a = a.clone();
    let mut b = b.clone();

    a.access_mask = a.access_mask & !(delegations::IGNORED_ACCESS_RIGHTS);
    b.access_mask = b.access_mask & !(delegations::IGNORED_ACCESS_RIGHTS);

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