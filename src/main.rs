mod connection;
use connection::{LdapConnection, LdapCredentials};
use windows::Win32::Networking::Ldap::LDAP_PORT;
use clap::{App, Arg};

fn main() {
    let default_port = format!("{}", LDAP_PORT);
    let app = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("server")
                .help("(explicit server) Non-default LDAP server hostname or IP")
                .long("server")
                .short('s')
                .number_of_values(1)
        )
        .arg(
            Arg::new("port")
                .help("(explicit server) Non-default LDAP port")
                .long("port")
                .number_of_values(1)
                .default_value(&default_port)
        )
        .arg(
            Arg::new("domain")
                .help("(explicit credentials) Non-implicit Domain name")
                .long("domain")
                .short('d')
                .number_of_values(1)
                .requires("username")
        )
        .arg(
            Arg::new("username")
                .help("(explicit credentials) Non-implicit User name")
                .long("user")
                .short('u')
                .number_of_values(1)
                .requires("domain")
        )
        .arg(
            Arg::new("password")
                .help("(explicit credentials) Non-Implicit Password")
                .long("password")
                .short('p')
                .number_of_values(1)
                .requires_all(&["domain","username"])
        );

    let args = app.get_matches();
    let server= args.value_of("server");
    let port = args.value_of("port").expect("no port set");
    let port = match port.parse::<u16>() {
        Ok(n) => n,
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
        Err((code, msg)) => {
            eprintln!("Unable to connect to \"{}:{}\" : {}", server.unwrap_or("default"), port, msg);
            std::process::exit(code as i32);
        }
    };

    if let Err((code, msg)) = conn.destroy() {
        eprintln!("Error when closing connection to \"{}:{}\" : {}", server.unwrap_or("default"), port, msg);
        std::process::exit(code as i32);
    }
    println!("Ok!");
}
