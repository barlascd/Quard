use crate::models::SecurityEvent;

pub fn validate_event(event: &SecurityEvent) -> Result<(), String> {
    event.validate()
}
