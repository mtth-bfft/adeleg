mod utils;
mod error;
mod schema;
mod delegations;
mod engine;
mod gui;

use std::io::Write;
use std::collections::HashMap;
use engine::PrincipalType;
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{Command, Arg};
use authz::Sid;
use winldap::connection::LdapConnection;
use crate::gui::run_gui;
use crate::engine::{Engine, AdelegResult};
use crate::error::AdelegError;
use crate::delegations::DelegationLocation;

fn main() {
    if std::env::args().count() <= 1 {
        run_gui();
        return;
    }

    let default_port = format!("{}", LDAP_PORT);
    let app = Command::new(env!("CARGO_PKG_NAME"))
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
            Arg::new("text")
            .help("Output as text (default is GUI if there is no commandline argument")
            .long("text")
            .takes_value(false)
        ).arg(
            Arg::new("csv")
                .help("Write output into a CSV file")
                .takes_value(true)
                .number_of_values(1)
                .long("csv")
        ).arg(
            Arg::new("show_builtin")
            .help("Include built-in delegations in the output")
            .long("show-builtin")
        ).arg(
            Arg::new("show_warning_unreadable")
            .help("Show unreadable security descriptors as warnings")
            .long("show-warning-unreadable")
        ).arg(
            Arg::new("show_raw")
                .help("Show unresolved ACE contents")
                .long("show-raw")
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
    let mut password = String::with_capacity(100);
    let credentials = match (args.value_of("domain"),
                             args.value_of("username"),
                             args.value_of("password")) {
        (Some(d), Some(u), None) | (Some(d), Some(u), Some("*")) => {
            crate::utils::read_password(&mut password, &format!("Password for {}\\{}", d, u));
            Some((d, u, password.as_str()))
        },
        (Some(d), Some(u), Some(p)) => Some((d, u, p)),
        _ => None,
    };

    let (server, port) = if let Some(server) = server {
        (server.to_owned(), port)
    } else {
        if let Some((server, port)) = utils::get_gc_domain_controller() {
            (server, port)
        } else {
            eprintln!(" [!] Unable to find a domain controller automatically, please specify one manually using --server");
            std::process::exit(1);
        }
    };

    let conn = match LdapConnection::new(&server, port, credentials) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Unable to establish LDAP connection to \"{}:{}\" : {}", server, port, e);
            std::process::exit(1);
        }
    };

    let mut engine = Engine::new(&conn, !args.is_present("show_raw"));
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
            eprintln!(" [!] Unable to scan for delegations: {}", e);
            std::process::exit(1);
        }
    };

    let show_builtin = args.is_present("show_builtin");
    let show_warning_unreadable = args.is_present("show_warning_unreadable");
    let mut warning_unreadable_count = 0;
    if let Some(csv_path) = args.value_of("csv") {
        let output: Box<dyn std::io::Write> = if csv_path == "-" {
            Box::new(std::io::stdout())
        } else {
            match std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(csv_path) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    eprintln!(" [!] Unable to open output CSV file {} : {}", csv_path, e);
                    std::process::exit(1);
                }
            }
        };
        let mut writer = csv::Writer::from_writer(output);
        writer.write_record(&[
            "Resource",
            "Trustee",
            "Trustee type",
            "Category",
            "Details",
        ]).expect("unable to write CSV record");
        for (location, res) in &res {
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    warning_unreadable_count += 1;
                    if show_warning_unreadable {
                        writer.write_record(&[
                            location.to_string().as_str(),
                            "Global",
                            "External",
                            "Warning",
                            &e.to_string(),
                        ]).expect("unable to write CSV record");
                    }
                    continue;
                },
            };
            if let Some(owner) = &res.owner {
                let (dn, ptype) = engine.resolve_sid(&owner).unwrap_or((owner.to_string(), PrincipalType::External));
                writer.write_record(&[
                    location.to_string().as_str(),
                    &dn,
                    &ptype.to_string(),
                    "Owner",
                    "This principal owns the object, which implicitly grants them full control over it",
                ]).expect("unable to write CSV record");
            }
            if res.dacl_protected {
                writer.write_record(&[
                    location.to_string().as_str(),
                    "Global",
                    "External",
                    "Warning",
                    "DACL is configured to block inheritance of parent container ACEs",
                ]).expect("unable to write CSV record");
            }
            if let Some(non_canonical_ace) = &res.non_canonical_ace {
                writer.write_record(&[
                    location.to_string().as_str(),
                    "Global",
                    "External",
                    "Warning",
                    &format!("ACL is not in canonical order, e.g. this ACE is out of order: {}", non_canonical_ace),
                ]).expect("unable to write CSV record");
            }
            for ace in &res.deleted_trustee {
                writer.write_record(&[
                    location.to_string().as_str(),
                    &ace.trustee.to_string(),
                    "External",
                    "Warning",
                    "The trustee linked to this delegation does not exist anymore, it should be cleaned up",
                ]).expect("unable to write CSV record");
            }
            for ace in &res.orphan_aces {
                let (dn, ptype) = engine.resolve_sid(&ace.trustee).unwrap_or((ace.trustee.to_string(), PrincipalType::External));
                writer.write_record(&[
                    location.to_string().as_str(),
                    &dn,
                    &ptype.to_string(),
                    if ace.grants_access() { "Allow ACE" } else { "Deny ACE" },
                    engine.describe_ace(
                        ace.access_mask,
                        ace.get_object_type(),
                        ace.get_inherited_object_type(),
                        ace.get_container_inherit(),
                        ace.get_inherit_only()
                    ).as_str(),
                ]).expect("unable to write CSV record");
            }
            for ace in &res.missing_aces {
                let (dn, ptype) = engine.resolve_sid(&ace.trustee).unwrap_or((ace.trustee.to_string(), PrincipalType::External));
                writer.write_record(&[
                    location.to_string().as_str(),
                    &dn,
                    &ptype.to_string(),
                    if ace.grants_access() { "Missing allow ACE" } else { "Missing deny ACE" },
                    engine.describe_ace(
                        ace.access_mask,
                        ace.get_object_type(),
                        ace.get_inherited_object_type(),
                        ace.get_container_inherit(),
                        ace.get_inherit_only()
                    ).as_str(),
                ]).expect("unable to write CSV record");
            }
            for (deleg, trustee, _) in &res.delegations {
                if deleg.builtin && !show_builtin {
                    continue;
                }
                let (dn, ptype) = engine.resolve_sid(trustee).unwrap_or((trustee.to_string(), PrincipalType::External));
                writer.write_record(&[
                    location.to_string().as_str(),
                    &dn,
                    &ptype.to_string(),
                    if deleg.builtin { "Built-in" } else { "Delegation" },
                    engine.describe_delegation_rights(&deleg.rights).as_str(),
                ]).expect("unable to write CSV record");
            }
        }

        drop(writer);
        let _ = std::io::stdout().flush();
        if !show_warning_unreadable && warning_unreadable_count > 0 {
            eprintln!("\n [!] {} security descriptors could not be read, use --show-warning-unreadable to see where", warning_unreadable_count);
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
                if res.deleted_trustee.is_empty() {
                    warning_count += 1;
                }
                if let Some(owner) = &res.owner {
                    let entry = reindexed.entry(owner.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                owner: None,
                                dacl_protected: false,
                                non_canonical_ace: None,
                                deleted_trustee: vec![],
                                orphan_aces: vec![],
                                missing_aces: vec![],
                                delegations: vec![],
                            }
                        });
                    entry.owner = Some(owner.clone());
                }
                for ace in res.orphan_aces {
                    let entry = reindexed.entry(ace.trustee.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                owner: None,
                                dacl_protected: false,
                                non_canonical_ace: None,
                                deleted_trustee: vec![],
                                orphan_aces: vec![],
                                missing_aces: vec![],
                                delegations: vec![],
                            }
                        });
                    entry.orphan_aces.push(ace);
                }
                for ace in res.missing_aces {
                    let entry = reindexed.entry(ace.trustee.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                owner: None,
                                dacl_protected: false,
                                non_canonical_ace: None,
                                deleted_trustee: vec![],
                                orphan_aces: vec![],
                                missing_aces: vec![],
                                delegations: vec![],
                            }
                        });
                    entry.missing_aces.push(ace);
                }
                for (deleg, trustee, aces) in res.delegations {
                    if deleg.builtin && !show_builtin {
                        continue;
                    }
                    let entry = reindexed.entry(trustee.clone())
                        .or_default()
                        .entry(location.clone())
                        .or_insert_with(|| {
                            AdelegResult {
                                owner: None,
                                dacl_protected: false,
                                non_canonical_ace: None,
                                deleted_trustee: vec![],
                                orphan_aces: vec![],
                                missing_aces: vec![],
                                delegations: vec![],
                            }
                        });
                    entry.delegations.push((deleg, trustee, aces));
                }
            } else {
                warning_count += 1;
            }
        }
        for (trustee, locations) in &reindexed {
            println!("\n=== {}", engine.resolve_sid(trustee).map(|(dn, _)| dn).unwrap_or(trustee.to_string()));
            for (location, res) in locations.iter() {
                println!("       {} :", location);
                if res.owner.as_ref() == Some(trustee) {
                    println!("            Owner");
                }
                for ace in &res.orphan_aces {
                    println!("            {} ACE {}",
                        if ace.grants_access() { "Allow" } else { "Deny" },
                        engine.describe_ace(
                            ace.access_mask,
                            ace.get_object_type(),
                            ace.get_inherited_object_type(),
                            ace.get_container_inherit(),
                            ace.get_inherit_only()
                    ));
                }
                for ace in &res.missing_aces {
                    println!("            Missing {} ACE {}",
                        if ace.grants_access() { "allow" } else { "deny" },
                        engine.describe_ace(
                            ace.access_mask,
                            ace.get_object_type(),
                            ace.get_inherited_object_type(),
                            ace.get_container_inherit(),
                            ace.get_inherit_only()
                    ));
                }
                for (delegation, _, _) in &res.delegations {
                    if !show_builtin && delegation.builtin {
                        continue;
                    }
                    println!("            Documented delegation: {}",
                        engine.describe_delegation_rights(&delegation.rights));
                }
            }
        }
        if warning_count > 0 {
            let _ = std::io::stdout().flush();
            eprintln!("\n [!] {} warnings were generated during analysis, some results may be incomplete. Use the resource view to see warnings.", warning_count);
        }
    } else {
        let mut res: Vec<(&DelegationLocation, &Result<AdelegResult, AdelegError>)> = res.iter().collect();
        res.sort_by(|(loc_a, _), (loc_b, _)| loc_a.cmp(loc_b));
        for (location, res) in res {
            if let Ok(res) = &res {
                if !res.needs_to_be_displayed(show_builtin) {
                    continue;
                }
            } else {
                warning_unreadable_count += 1;
                if !show_warning_unreadable {
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
            if let Some(owner) = &res.owner {
                println!("       Owner: {}", engine.resolve_sid(owner).map(|(dn, _)| dn).unwrap_or(owner.to_string()));
            }
            if res.dacl_protected {
                println!("       /!\\ ACL is configured to block inheritance of parent container ACEs");
            }
            if let Some(ace) = &res.non_canonical_ace {
                println!("       /!\\ ACL is not in canonical order, e.g. see ACE: {}", ace);
            }
            if !res.deleted_trustee.is_empty() {
                println!("       /!\\ ACEs for trustees which do not exist anymore and should be cleaned up:");
                for ace in &res.deleted_trustee {
                    println!("         {}", &ace.trustee);
                }
            }
            if !res.orphan_aces.is_empty() {
                println!("       ACEs found:");
                for ace in &res.orphan_aces {
                    println!("         {} {} : {}",
                        if ace.grants_access() { "Allow" } else { "Deny" },
                        engine.resolve_sid(&ace.trustee).map(|(dn, _)| dn).unwrap_or(ace.trustee.to_string()),
                        engine.describe_ace(
                            ace.access_mask,
                            ace.get_object_type(),
                            ace.get_inherited_object_type(),
                            ace.get_container_inherit(),
                            ace.get_inherit_only()
                        ));
                }
            }
            if !res.missing_aces.is_empty() {
                println!("       ACEs missing:");
                for ace in &res.missing_aces {
                    println!("         {} {} : {}",
                        if ace.grants_access() { "Allow" } else { "Deny" },
                        engine.resolve_sid(&ace.trustee).map(|(dn, _)| dn).unwrap_or(ace.trustee.to_string()),
                        engine.describe_ace(
                            ace.access_mask,
                            ace.get_object_type(),
                            ace.get_inherited_object_type(),
                            ace.get_container_inherit(),
                            ace.get_inherit_only()
                        ));
                }
            }
            if res.delegations.iter().any(|(d, _, _)| !d.builtin) ||
                    (!res.delegations.is_empty() && show_builtin) {
                println!("       Documented delegations:");
                for (delegation, trustee, _) in &res.delegations {
                    if !show_builtin && delegation.builtin {
                        continue;
                    }
                    println!("         {} : {}", engine.resolve_sid(&trustee).map(|(dn, _)| dn).unwrap_or(trustee.to_string()),
                        engine.describe_delegation_rights(&delegation.rights));
                }
            }
        }

        if !show_warning_unreadable && warning_unreadable_count > 0 {
            let _= std::io::stdout().flush();
            eprintln!("\n [!] {} security descriptors could not be read, use --show-warning-unreadable to see where", warning_unreadable_count);
        }
    }
}