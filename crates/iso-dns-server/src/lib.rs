//! iso-dns-server crate.

/// Returns the name of this crate.
pub fn name() -> &'static str {
    "iso-dns-server"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_reports_name() {
        assert_eq!(name(), "iso-dns-server");
    }
}
