//! Which host gets a VM. Filter to the hosts that can take it, then least
//! loaded first. Capacity is only a hint here: the host enforces it, and a
//! create that loses a race for the last slot moves to the next candidate.

use crate::store::HostRow;

/// Candidate hosts for `template`, best first. A `pin` restricts to one host.
pub fn candidates<'a>(hosts: &'a [HostRow], template: &str, pin: Option<&str>) -> Vec<&'a HostRow> {
    let mut out: Vec<&HostRow> = hosts
        .iter()
        .filter(|h| h.healthy)
        .filter(|h| pin.is_none_or(|p| p == h.name))
        .filter(|h| h.templates.iter().any(|t| t == template))
        .filter(|h| h.slots_free > 0)
        .collect();
    out.sort_by(|a, b| {
        let la = load(a);
        let lb = load(b);
        la.partial_cmp(&lb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn load(h: &HostRow) -> f64 {
    if h.slots_total == 0 {
        return 1.0;
    }
    1.0 - (h.slots_free as f64 / h.slots_total as f64)
}

/// Whether any host at all, healthy or not, has `template`: the difference
/// between "unknown template" and "no capacity right now".
pub fn template_known(hosts: &[HostRow], template: &str) -> bool {
    hosts
        .iter()
        .any(|h| h.templates.iter().any(|t| t == template))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, healthy: bool, free: u32, total: u32, templates: &[&str]) -> HostRow {
        HostRow {
            name: name.into(),
            url: String::new(),
            healthy,
            last_seen: None,
            slots_free: free,
            slots_total: total,
            pool_data_percent: 0.0,
            templates: templates.iter().map(|s| s.to_string()).collect(),
            orphans: 0,
            last_error: None,
        }
    }

    #[test]
    fn least_loaded_host_with_the_template_first() {
        let hosts = vec![
            host("a", true, 2, 8, &["base"]),
            host("b", true, 6, 8, &["base", "debian"]),
            host("c", false, 8, 8, &["base"]),
            host("d", true, 0, 8, &["base"]),
        ];
        let names: Vec<_> = candidates(&hosts, "base", None)
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["b", "a"],
            "unhealthy and full hosts are skipped"
        );
        let names: Vec<_> = candidates(&hosts, "debian", None)
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(names, vec!["b"]);
        let names: Vec<_> = candidates(&hosts, "base", Some("a"))
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        assert_eq!(names, vec!["a"]);
        assert!(candidates(&hosts, "nope", None).is_empty());
        assert!(template_known(&hosts, "debian"));
        assert!(!template_known(&hosts, "nope"));
    }
}
