//#![windows_subsystem = "windows"]

mod utils;
mod error;
mod schema;
mod delegations;
mod engine;
mod gui;

use std::collections::HashMap;
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};
use authz::Sid;
use winldap::connection::{LdapConnection, LdapCredentials};
use crate::gui::run_gui;
use crate::engine::{Engine, AdelegResult};
use crate::error::AdelegError;
use crate::delegations::DelegationLocation;

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
            Arg::new("index")
                .help("Index view by trustee or resources (default is by resources)")
                .long("index")
                .takes_value(true)
                .default_value("resources")
                .possible_values(&["resources", "trustees"])                
        ).arg(
            Arg::new("csv")
                .help("Format output as CSV")
                .long("csv")
        ).arg(
            Arg::new("show_builtin")
            .help("Include built-in delegations in the output")
            .long("show-builtin")
        ).arg(
            Arg::new("view_raw")
                .help("View unresolved ACE contents")
                .long("view-raw")
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

    let mut engine = Engine::new(&conn, !args.is_present("view_raw"));
    engine.load_delegation_json(engine::BUILTIN_ACES).expect("unable to parse builtin delegations");

    if let Some(input_filepaths) = args.values_of("templates") {
        for input_filepath in input_filepaths.into_iter() {
            let json = match std::fs::read_to_string(input_filepath) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(" [!] Unable to open template file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = engine.load_template_json(&json) {
                eprintln!(" [!] Unable to parse template file {} : {}", input_filepath, e);
                std::process::exit(1);
            }
        }
    }

    if let Some(input_files) = args.values_of("delegations") {
        for input_filepath in input_files.into_iter() {
            let json = match std::fs::read_to_string(input_filepath) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(" [!] Unable to open delegation file {} : {}", input_filepath, e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = engine.load_delegation_json(&json) {
                eprintln!(" [!] Unable to parse delegation file {} : {}", input_filepath, e);
                std::process::exit(1);
            }
        }
    }

    let res = match engine.run() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("An error occurred while scanning for delegations: {}", e);
            std::process::exit(1);
        }
    };

    if args.is_present("csv") {
        let mut writer = csv::Writer::from_writer(std::io::stdout());
        for (location, res) in &res {
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    writer.write_record(&[
                        location.to_string().as_str(),
                        "",
                        "Warning",
                        &e.to_string(),
                    ]).expect("unable to write CSV record");
                    continue;
                },
            };
            if let Some(non_canonical_ace) = &res.non_canonical_ace {
                writer.write_record(&[
                    location.to_string().as_str(),
                    "",
                    "Warning",
                    &format!("ACL is not in canonical order, e.g. this ACE is out of order: {}", non_canonical_ace),
                ]).expect("unable to write CSV record");
            }
            for (deleg, trustee) in &res.delegations_missing {
                writer.write_record(&[
                    location.to_string().as_str(),
                    engine.resolve_sid(&trustee).as_str(),
                    "Delegation (missing!)",
                    engine.describe_delegation_rights(&deleg.rights).as_str(),
                ]).expect("unable to write CSV record");
            }
            for ace in &res.orphan_aces {
                writer.write_record(&[
                    location.to_string().as_str(),
                    engine.resolve_sid(&ace.trustee).as_str(),
                    if ace.grants_access() { "Allow ACE" } else { "Deny ACE" },
                    engine.describe_ace(&ace).as_str(),
                ]).expect("unable to write CSV record");
            }
            for (deleg, trustee, _) in &res.delegations_found {
                writer.write_record(&[
                    location.to_string().as_str(),
                    engine.resolve_sid(&trustee).as_str(),
                    "Delegation",
                    engine.describe_delegation_rights(&deleg.rights).as_str(),
                ]).expect("unable to write CSV record");
            }
        }
    }
    else if args.value_of("index").unwrap_or("") == "trustees" {
        let mut warning_count = 0;
        let mut reindexed: HashMap<Sid, HashMap<DelegationLocation, AdelegResult>> = HashMap::new();
        for (location, res) in res.into_iter() {
            if let Ok(res) = res {
                if res.non_canonical_ace.is_some() {
                    warning_count += 1;
                }
                for ace in res.orphan_aces {
                    let entry = reindexed.entry(ace.trustee.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                non_canonical_ace: None,
                                orphan_aces: vec![],
                                delegations_found: vec![],
                                delegations_missing: vec![],
                            }
                        });
                    entry.orphan_aces.push(ace);
                }
                for (deleg, trustee, aces) in res.delegations_found {
                    let entry = reindexed.entry(trustee.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                non_canonical_ace: None,
                                orphan_aces: vec![],
                                delegations_found: vec![],
                                delegations_missing: vec![],
                            }
                        });
                    entry.delegations_found.push((deleg, trustee, aces));
                }
            } else {
                warning_count += 1;
            }
        }
        if warning_count > 0 {
            eprintln!(" [!] {} warnings were generated during analysis, some results may be incomplete. Use the resource view to see warnings.", warning_count);
        }
        for (trustee, locations) in &reindexed {
            println!("\n=== {}", engine.resolve_sid(trustee));
            for (location, res) in locations.iter() {
                println!("       {} :", location);
                for ace in &res.orphan_aces {
                    println!("            {} ACE {}",
                        if ace.grants_access() { "Allow" } else { "Deny" },
                        engine.describe_ace(&ace));
                }
                for (delegation, _) in &res.delegations_missing {
                    println!("            Delegation missing: {}",
                        engine.describe_delegation_rights(&delegation.rights));
                }
                for (delegation, _, _) in &res.delegations_found {
                    if !args.is_present("show_builtin") && delegation.builtin {
                        continue;
                    }
                    println!("            Documented delegation: {}",
                        engine.describe_delegation_rights(&delegation.rights));
                }
            }
        }
        if warning_count > 0 {
            eprintln!("\n [!] {} warnings were generated during analysis, some results may be incomplete. Use the resource view to see warnings.", warning_count);
        }
    } else {
        let mut res: Vec<(&DelegationLocation, &Result<AdelegResult, AdelegError>)> = res.iter().collect();
        res.sort_by(|(loc_a, _), (loc_b, _)| loc_a.cmp(loc_b));
        for (location, res) in res {
            if let Ok(res) = &res {
                if res.non_canonical_ace.is_none() &&
                    res.orphan_aces.is_empty() &&
                    res.delegations_missing.iter().all(|(d, __)| d.builtin) &&
                    res.delegations_found.iter().all(|(d, _, _)| d.builtin) &&
                    (res.delegations_found.is_empty() || !args.is_present("show_builtin")) {
                    continue;
                }
            }

            println!("\n=== {}", &location);
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    println!("       /!\\ {}", e);
                    continue;
                },
            };
            if let Some(ace) = &res.non_canonical_ace {
                println!("       /!\\ ACL is not in canonical order, e.g. see ACE: {}", ace);
            }

            if !res.orphan_aces.is_empty() {
                println!("       ACEs:");
                for ace in &res.orphan_aces {
                    println!("         {} {} : {}",
                        if ace.grants_access() { "Allow" } else { "Deny" },
                        engine.resolve_sid(&ace.trustee),
                        engine.describe_ace(&ace));
                }
            }
            if res.delegations_missing.iter().any(|(d, __)| !d.builtin) {
                println!("       Delegations missing:");
                for (delegation, trustee) in &res.delegations_missing {
                    if delegation.builtin {
                        continue;
                    }
                    println!("         {} : {}", engine.resolve_sid(&trustee),
                        engine.describe_delegation_rights(&delegation.rights));
                }
            }
            if res.delegations_found.iter().any(|(d, _, _)| !d.builtin) ||
                    (!res.delegations_found.is_empty() && args.is_present("show_builtin")) {
                println!("       Documented delegations:");
                for (delegation, trustee, aces) in &res.delegations_found {
                    if !args.is_present("show_builtin") && delegation.builtin {
                        continue;
                    }
                    println!("         {} : {}", engine.resolve_sid(&trustee),
                        engine.describe_delegation_rights(&delegation.rights));
                }
            }
        }
    }
}