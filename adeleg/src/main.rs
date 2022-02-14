mod utils;
mod schema;
mod delegations;
use winldap::connection::{LdapConnection, LdapCredentials};
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};
use crate::schema::Schema;
use crate::delegations::get_explicit_delegations;
use crate::utils::{get_forest_sid, get_adminsdholder_sd};

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

    for naming_context in conn.get_naming_contexts() {
        println!("Fetching security descriptors of naming context {}", naming_context);
        let delegations = match get_explicit_delegations(&conn, naming_context, &forest_sid, &schema, &adminsdholder_sd) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Error when fetching security descriptors of {} : {}", naming_context, e);
                std::process::exit(1);
            },
        };
    }

    if let Err(e) = conn.destroy() {
        eprintln!("Error when closing connection to \"{}:{}\" : {}", server.unwrap_or("default"), port, e);
        std::process::exit(1);
    }
    println!("Ok!");
}
