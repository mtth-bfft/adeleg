use windows::Win32::Security::{CONTAINER_INHERIT_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, INHERIT_ONLY_ACE};
use windows::Win32::Networking::Ldap::{LDAP_SCOPE_BASE, LDAP_SCOPE_SUBTREE, LDAP_SCOPE_ONELEVEL};
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Networking::ActiveDirectory::{DsGetDcNameW, DS_GC_SERVER_REQUIRED, DS_DIRECTORY_SERVICE_REQUIRED, DS_RETURN_DNS_NAME, DOMAIN_CONTROLLER_INFOW};
use windows::Win32::System::Console::{GetConsoleMode, CONSOLE_MODE, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT};
use windows::Win32::Foundation::ERROR_SUCCESS;
use std::os::windows::prelude::AsRawHandle;
use std::io::{Write, BufRead};
use core::borrow::Borrow;
use core::ptr::null_mut;
use authz::{Ace, Sid, SecurityDescriptor, Guid};
use winldap::connection::LdapConnection;
use winldap::search::{LdapSearch, LdapEntry};
use winldap::error::LdapError;
use winldap::utils::get_attr_str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub sid: Sid,
    pub distinguished_name: String,
    pub netbios_name: String,
}

pub(crate) fn read_password(out: &mut String, prompt: &str) {
    let stdout = std::io::stdout();
    let stdin = std::io::stdin();
    let mut stdout = stdout.lock();
    let stdin = stdin.lock();

    print!("{} : ", prompt);
    let _ = stdout.flush();
    let h_console = windows::Win32::Foundation::HANDLE(stdin.as_raw_handle() as isize);
    let mut prev_stdin_mode = CONSOLE_MODE::default();
    let succeeded = unsafe { GetConsoleMode(h_console, &mut prev_stdin_mode as *mut _) };
    if !succeeded.as_bool() {
        eprintln!("Unable to setup console");
        std::process::exit(1);
    }
    let succeeded = unsafe { SetConsoleMode(h_console, CONSOLE_MODE((prev_stdin_mode.0 | ENABLE_LINE_INPUT.0 | ENABLE_PROCESSED_INPUT.0) & !ENABLE_ECHO_INPUT.0)) };
    if !succeeded.as_bool() {
        eprintln!("Unable to setup console");
        std::process::exit(1);
    }
    let _ = std::io::BufReader::new(stdin).read_line(out);
    let succeeded = unsafe { SetConsoleMode(h_console, prev_stdin_mode) };
    if !succeeded.as_bool() {
        eprintln!("Unable to setup console");
        std::process::exit(1);
    }
    println!();
    if out.ends_with("\r\n") {
        out.pop();
        out.pop();
    } else if out.ends_with("\n") {
        out.pop();
    }
}

pub(crate) fn get_gc_domain_controller() -> Option<(String, u16)> {
    let mut dc_info_ptr: *mut DOMAIN_CONTROLLER_INFOW = null_mut();
    let res = unsafe { DsGetDcNameW(None, None, None, None, DS_GC_SERVER_REQUIRED | DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &mut dc_info_ptr as *mut _) };
    if res != ERROR_SUCCESS.0 || dc_info_ptr.is_null() {
        return None;
    }
    let server = unsafe { pwstr_to_str((*dc_info_ptr).DomainControllerName.0) };
    unsafe { NetApiBufferFree(Some(dc_info_ptr as *mut _)); }
    let server = server.trim_start_matches('\\');
    Some(if let Some((host, port)) = server.split_once(':') {
        (host.to_owned(), port.parse().unwrap_or(389))
    } else {
        (server.to_owned(), 389)
    })
}

pub(crate) fn pwstr_to_str(ptr: *const u16) -> String {
    let mut len = 0;
    unsafe {
        while *(ptr.add(len)) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { &*(std::ptr::slice_from_raw_parts(ptr, len)) };
    String::from_utf16_lossy(slice)
}

pub(crate) fn get_attr_sids<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Vec<Sid>, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        Ok(vals.iter().map(|s| Sid::from_bytes(s).unwrap()).collect())
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_sid<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Sid, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            Ok(Sid::from_bytes(&vals[0]).unwrap())
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_sd<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<SecurityDescriptor, LdapError> {
    let (dn, attrs) = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        (&search_results[0].borrow().dn, &search_results[0].borrow().attrs)
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: dn.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            match SecurityDescriptor::from_bytes(&vals[0]) {
                Ok(sd) => Ok(sd),
                Err(e) => {
                    eprintln!(" [!] Unable to parse security descriptor at {} : {}", &dn, e);
                    return Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() });
                }
            }
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: dn.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_attr_guid<T: Borrow<LdapEntry>>(search_results: &[T], base: &str, attr_name: &str) -> Result<Guid, LdapError> {
    let attrs = if search_results.len() > 1 {
        return Err(LdapError::RequiredObjectCollision { dn: base.to_owned() });
    } else if search_results.len() == 0 {
        return Err(LdapError::RequiredObjectMissing { dn: base.to_owned() });
    } else {
        &search_results[0].borrow().attrs
    };

    if let Some(vals) = attrs.get(attr_name) {
        if vals.len() == 0 {
            return Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() });
        } else if vals.len() > 1 {
            return Err(LdapError::AttributeValuesCollision { dn: base.to_owned(), name: attr_name.to_owned(), val1: format!("{:?}", vals[0]), val2: format!("{:?}", vals[1]) });
        } else {
            let bytes = &vals[0];
            if bytes.len() != 16 {
                return Err(LdapError::UnableToParseGuid { dn: base.to_owned(), attr_name: attr_name.to_owned(), bytes: bytes.to_owned() });
            }
            Ok(Guid::from_values(
                u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
                u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
                bytes[8..16].try_into().unwrap()))
        }
    } else {
        Err(LdapError::RequiredAttributeMissing { dn: base.to_owned(), name: attr_name.to_owned() })
    }
}

pub(crate) fn get_domains(conn: &LdapConnection) -> Result<Vec<Domain>, LdapError> {
    let partitions_dn = format!("CN=Partitions,{}", conn.get_configuration_naming_context());
    let search = LdapSearch::new(&conn, Some(&partitions_dn), LDAP_SCOPE_ONELEVEL, Some("(&(nCName=*)(nETBIOSName=*))"), Some(&["nCName", "nETBIOSName"]), &[]);
    let partitions = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;

    let mut v = vec![];
    for partition in &partitions {
        let nc = get_attr_str(&[partition], &partition.dn, "ncname")?;
        let netbios_name = get_attr_str(&[partition], &partition.dn, "netbiosname")?;

        let mut search = LdapSearch::new(&conn, Some(&nc), LDAP_SCOPE_BASE, Some("(objectSid=*)"), Some(&["objectSid"]), &[]);
        if let Some(Ok(entry)) = search.next() {
            let sid= get_attr_sid(&[entry], &nc, "objectsid")?;
            v.push(Domain {
                distinguished_name: nc.to_owned(),
                sid,
                netbios_name,
            });
        }
    }
    Ok(v)
}

pub(crate) fn get_ace_derived_by_inheritance_from_schema(parent_aces: &[Ace], child_owner: &Sid, child_object_type: &Guid, force_inheritance: bool) -> Vec<Ace> {
    let mut res = vec![];
    for parent_ace in parent_aces {
        if !force_inheritance && (parent_ace.flags & CONTAINER_INHERIT_ACE.0 as u8) == 0 {
            continue;
        }
        if let Some(guid) = parent_ace.get_inherited_object_type() {
            if guid != child_object_type && (parent_ace.flags & NO_PROPAGATE_INHERIT_ACE.0 as u8) != 0 {
                continue;
            }
        }

        let mut flags = parent_ace.flags;
        if (parent_ace.flags & NO_PROPAGATE_INHERIT_ACE.0 as u8) != 0 {
            flags &= !(CONTAINER_INHERIT_ACE.0 as u8 | OBJECT_INHERIT_ACE.0 as u8);
        }

        // Creator Owner SID gets replaced by the current owner
        if parent_ace.trustee == Sid::try_from("S-1-3-0").unwrap() {
            res.push(Ace {
                trustee: child_owner.clone(),
                access_mask: parent_ace.access_mask,
                flags: flags & !(CONTAINER_INHERIT_ACE.0 as u8 | OBJECT_INHERIT_ACE.0 as u8),
                type_specific: parent_ace.type_specific.clone(),
            });
            res.push(Ace {
                trustee: parent_ace.trustee.clone(),
                access_mask: parent_ace.access_mask,
                flags: flags | (INHERIT_ONLY_ACE.0 as u8),
                type_specific: parent_ace.type_specific.clone(),
            });
        } else {
            res.push(Ace {
                trustee: parent_ace.trustee.clone(),
                access_mask: parent_ace.access_mask,
                flags,
                type_specific: parent_ace.type_specific.clone(),
            });
        }
    }
    res
}

pub(crate) fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
    }
}

pub(crate) fn replace_suffix_case_insensitive<'a>(haystack: &'a str, suffix: &str, replacement: &str) -> String {
    if haystack.to_lowercase().ends_with(&suffix.to_lowercase()) && haystack.is_char_boundary(haystack.len() - suffix.len()) {
        format!("{}{}", &haystack[..haystack.len() - suffix.len()], replacement)
    } else {
        haystack.to_owned()
    }
}

pub(crate) fn ends_with_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().ends_with(&needle.to_lowercase())
}

pub(crate) fn get_parent_container<'a>(dn: &'a str, naming_context: &str) -> Option<&'a str> {
    if let Some((_, parent)) = dn.split_once(',') {
        if ends_with_case_insensitive(parent, naming_context) {
            return Some(parent);
        }
    }
    None
}

pub(crate) fn resolve_samaccountname_to_sid(ldap: &LdapConnection, samaccountname: &str, domain: &Domain) -> Result<Sid, LdapError> {
    let search = LdapSearch::new(&ldap, Some(&domain.distinguished_name), LDAP_SCOPE_SUBTREE, Some(&format!("(samAccountName={})", samaccountname)), Some(&["objectSid"]), &[]);
    let res = search.collect::<Result<Vec<LdapEntry>, LdapError>>()?;
    get_attr_sid(&res, &domain.distinguished_name, "objectsid")
}

pub(crate) fn ace_equivalent(a: &Ace, b: &Ace) -> bool {
    if a == b {
        return true;
    }

    let mut a = a.clone();
    let mut b = b.clone();

    a.access_mask = a.access_mask & !(crate::engine::IGNORED_ACCESS_RIGHTS);
    b.access_mask = b.access_mask & !(crate::engine::IGNORED_ACCESS_RIGHTS);
    a.flags = a.flags & !(crate::engine::IGNORED_ACE_FLAGS);
    b.flags = b.flags & !(crate::engine::IGNORED_ACE_FLAGS);

    a == b
}
