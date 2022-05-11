//#![windows_subsystem = "windows"]

mod utils;
mod schema;
mod delegations;
mod engine;
mod gui;

use std::collections::{HashMap, HashSet};
use authz::{Ace, Sid};
use delegations::{DelegationLocation, DelegationTemplate};
use winldap::connection::{LdapConnection, LdapCredentials};
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};
use crate::gui::run_gui;
use crate::schema::Schema;
use crate::engine::Engine;
use crate::delegations::{get_explicit_aces, get_schema_aces, Delegation};
use crate::utils::{get_adminsdholder_aces, get_domains};

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

    let mut engine = Engine::new(&conn);

    if let Some(input_filepaths) = args.values_of("templates") {
        for input_filepath in input_filepaths.into_iter() {
            if let Err(e) = engine.register_template(input_filepath) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(input_files) = args.values_of("delegations") {
        for input_filepath in input_files.into_iter() {
            if let Err(e) = engine.register_delegation(input_filepath) {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }

    let mut res = engine.run();

    if let Some(trustee) = args.value_of("trustee") {
        let sid = match engine.resolve_str_to_sid(trustee) {
            Some(sid) => sid,
            None => {
                eprintln!("Error: Could not resolve trustee \"{}\" (valid syntaxes are SIDs (S-1-5-21-*), distinguished names, and NetbiosName\\samAccountName)", trustee);
                std::process::exit(1);
            },
        };
        let bak = res.get(&sid).cloned().unwrap_or_default();
        res.clear();
    }

    for (trustee, locations) in &res {
        println!("\n======= {}", engine.resolve_sid(trustee));
        for (location, (deleg_found, deleg_missing, orphan_aces)) in locations {
            println!(" > {:?}", location);
            if !deleg_found.is_empty() {
                println!("   Delegations in place:");
                for delegation in deleg_found {
                    println!("   {:?}", delegation);
                }
                println!("");
            }
            if !deleg_missing.is_empty() {
                println!("   Delegations missing:");
                for delegation in deleg_missing {
                    println!("   {:?}", delegation);
                }
                println!("");
            }
            if !orphan_aces.is_empty() {
                println!("   ACEs:");
                for ace in orphan_aces {
                    println!("   {:?}", ace);
                }
                println!("");
            }
        }
        println!("");
    }
}