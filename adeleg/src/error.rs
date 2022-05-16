use authz::AuthzError;
use winldap::error::LdapError;

#[derive(Debug, Clone)]
pub enum AdelegError {
    LdapQueryFailed(LdapError),
    UnableToParseDefaultSecurityDescriptor(AuthzError),
    UnresolvedSamAccountName(String),
}

impl core::fmt::Display for AdelegError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdelegError::LdapQueryFailed(e) => f.write_fmt(format_args!("unable to fetch information from LDAP, {}", e)),
            AdelegError::UnableToParseDefaultSecurityDescriptor(e) => f.write_fmt(format_args!("unable to parse this class defaultSecurityDescriptor, {}", e)),
            AdelegError::UnresolvedSamAccountName(name) => f.write_fmt(format_args!("could not find a principal with samAccountName \"{}\" anywhere", name)),
        }
    }
}