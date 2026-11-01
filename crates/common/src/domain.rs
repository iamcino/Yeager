//! Domain list helpers shared by the Selected hosts and Custom exclusions
//! sheets: one place that decides what counts as a domain and how a list is
//! merged, so both lists behave the same way.

/// Longest domain name DNS allows.
pub const MAX_DOMAIN_LEN: usize = 253;

/// Turns user input like `https://www.Discord.com/app` or `*.example.com`
/// into a bare lowercase domain (`www.discord.com`, `example.com`).
///
/// Returns `None` for anything that is not a plausible domain: empty input,
/// `*`, `.`, `..`, names longer than 253 characters, names without a dot, or
/// labels with characters other than letters, digits and `-`.
pub fn normalize_domain(input: &str) -> Option<String> {
    let mut s = input.trim().to_ascii_lowercase();
    if let Some(i) = s.find("://") {
        s.drain(..i + 3);
    }
    if let Some(i) = s.find(['/', '?', '#', ':']) {
        s.truncate(i);
    }
    // A wildcard means "this domain and its subdomains", which is what every
    // entry already means.
    while let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    let s = s.trim_matches('.');
    let valid = s.len() <= MAX_DOMAIN_LEN
        && s.contains('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    valid.then(|| s.to_string())
}

/// Adds `domains` to `list`, then lowercases, de-duplicates and sorts the
/// whole list alphabetically. Returns how many new entries were added.
pub fn merge_domains<S: AsRef<str>>(list: &mut Vec<String>, domains: &[S]) -> usize {
    for d in list.iter_mut() {
        *d = d.trim().to_ascii_lowercase();
    }
    list.sort();
    list.dedup();
    let before = list.len();
    list.extend(domains.iter().filter_map(|d| normalize_domain(d.as_ref())));
    list.sort();
    list.dedup();
    list.len() - before
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_user_input() {
        assert_eq!(normalize_domain("  Discord.COM ").as_deref(), Some("discord.com"));
        assert_eq!(normalize_domain("https://www.Discord.com/app?x=1").as_deref(), Some("www.discord.com"));
        assert_eq!(normalize_domain("example.com:443").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("*.example.com").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("example.com.").as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_non_domains() {
        for bad in ["", "   ", "*", ".", "..", "*.", "*.*", "localhost", "a..b", "-a.com", "a b.com", "ex*ample.com"] {
            assert_eq!(normalize_domain(bad), None, "{bad:?} should be rejected");
        }
        let long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        assert!(long.len() > MAX_DOMAIN_LEN);
        assert_eq!(normalize_domain(&long), None);
    }

    #[test]
    fn merge_dedups_and_sorts() {
        let mut list = vec!["zeta.com".to_string(), "Alpha.com".to_string()];
        let added = merge_domains(&mut list, &["beta.com", "alpha.com", "BETA.com", "*"]);
        assert_eq!(added, 1);
        assert_eq!(list, ["alpha.com", "beta.com", "zeta.com"]);
        // Importing the same list again adds nothing (I2).
        assert_eq!(merge_domains(&mut list, &["beta.com"]), 0);
        assert_eq!(list.len(), 3);
    }
}
