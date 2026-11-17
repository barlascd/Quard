use crate::config::Config;

#[derive(Debug, PartialEq)]
pub enum IdentityStatus {
    Authenticated,
    Unauthorized,
}

pub fn check_identity(config: &Config, user_id: &str) -> IdentityStatus {
    if user_id.is_empty() {
        return IdentityStatus::Unauthorized;
    }
    if config.authorized_users.iter().any(|u| u == user_id) {
        IdentityStatus::Authenticated
    } else {
        IdentityStatus::Unauthorized
    }
}
