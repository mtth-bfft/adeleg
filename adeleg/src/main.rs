mod utils;
mod schema;
mod delegations;
use std::collections::HashMap;

use authz::{Ace, Sid};
use delegations::{DelegationLocation, DelegationTemplate};
use winldap::connection::{LdapConnection, LdapCredentials};
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};
use crate::schema::Schema;
use crate::delegations::{get_explicit_aces, get_schema_aces, Delegation};
use crate::utils::{get_forest_sid, get_adminsdholder_sd, pretty_print_ace};

fn main() {
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

    let forest_sid = match get_forest_sid(&conn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to fetch forest SID: {}", e);
            std::process::exit(1);
        }
    };

    let adminsdholder_sd = match get_adminsdholder_sd(&conn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to fetch AdminSDHolder security descriptor: {}", e);
            std::process::exit(1);
        }
    };

    let schema = match Schema::query(&conn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to fetch required information from schema: {}", e);
            std::process::exit(1);
        }
    };

    let templates: HashMap<String, DelegationTemplate> = {
        let mut res = HashMap::new();
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
                        for model in v.into_iter() {
                            res.insert(model.name.clone(), model);
                        }
                    },
                    Err(e) => {
                        eprintln!(" [!] Unable to parse template file {} : {}", input_filepath, e);
                        std::process::exit(1);
                    }
                }
            }
        }
        res
    };

    let delegations: Vec<Delegation> = {
        let mut res = vec![];
        if let Some(input_files) = args.values_of("delegations") {
            for input_filepath in input_files.into_iter() {
                let json = match std::fs::read_to_string(input_filepath) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!(" [!] Unable to open file {} : {}", input_filepath, e);
                        std::process::exit(1);
                    }
                };
                match Delegation::from_json(&json, &templates) {
                    Ok(mut v) => res.append(&mut v),
                    Err(e) => {
                        eprintln!(" [!] Unable to parse delegation file {} : {}", input_filepath, e);
                        std::process::exit(1);
                    }
                }
            }
        }
        res
    };

    let mut aces_found: HashMap<Sid, HashMap<DelegationLocation, Vec<Ace>>> = get_schema_aces(&schema, &forest_sid);

    for naming_context in conn.get_naming_contexts() {
        println!("Fetching security descriptors of naming context {}", naming_context);
        match get_explicit_aces(&conn, naming_context, &forest_sid, &schema, &adminsdholder_sd) {
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

    if let Err(e) = conn.destroy() {
        eprintln!("Error when closing connection to \"{}:{}\" : {}", server.unwrap_or(""), port, e);
        std::process::exit(1);
    }

    // Check which ACEs are explained by a delegation passed to us as input
    let mut delegations_in_input: HashMap<Sid, HashMap<DelegationLocation, Vec<(Delegation, Vec<Ace>)>>> = HashMap::new();
    for delegation in &delegations {
        for (location, aces) in delegation.derive_aces() {
            let sid = aces.get(0).expect("delegations should have at least one ACE").trustee.clone();
            delegations_in_input.entry(sid).or_insert(HashMap::new())
                .entry(location).or_insert(vec![])
                .push((delegation.clone(), aces));
        }
    }

    for (trustee, locations) in &aces_found {
        for (location, aces) in locations {
            let mut aces_explained: Vec<bool> = aces.iter().map(|_| false).collect();

            let expected_delegations = delegations_in_input.get(trustee)
                .and_then(|h| h.get(&location).map(|v| v.as_slice()))
                .unwrap_or(&[]);

            for (_, expected_aces) in expected_delegations {
                if is_ace_subset_and_in_order(&aces, &expected_aces) {
                    for ace in expected_aces {
                        aces_explained[aces.iter().position(|a| a == ace).unwrap()] = true;
                    }
                }
            }

            if aces_explained.iter().any(|b| !*b) {
                println!("====== Considering {} on {:?}", &trustee, &location);

                eprintln!(" [.] Expected ACEs:");
                for (delegation, aces) in expected_delegations {
                    for ace in aces {
                        eprintln!("          {:?} (from {})", pretty_print_ace(ace, &schema), delegation.template_name);
                    }
                }

                eprintln!(" [.] ACEs found:");
                for (i, ace) in aces.iter().enumerate() {
                    eprintln!("          {} {}", if aces_explained[i] { "[OK]" } else { "[!!]" }, pretty_print_ace(ace, &schema));
                }
            }
        }
    }
}

fn is_ace_subset_and_in_order(needle: &[Ace], haystack: &[Ace]) -> bool {
    let mut iter = haystack.iter();
    for needle_ace in needle {
        let mut found = false;
        loop {
            if let Some(haystack_ace) = iter.next() {
                if haystack_ace == needle_ace {
                    found = true;
                    break;
                }
            } else {
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}