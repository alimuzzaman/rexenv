//! Public aliases: a hostname that a site answers on in the SHARED nginx only.
//!
//! An extra domain (`site_domains`, v42) is a full rexenv name: it joins the
//! site's certificate, its Caddy edge route and, through its TLD, the resolver
//! route. That is why `--add` refuses a popular real TLD (`core::tld`): taking
//! `.online` into the resolver would hide every real `.online` site on the
//! machine. A public alias is the other case — a real public name whose DNS
//! and TLS belong to someone else (a front door that forwards to nginx with
//! the public `Host`). It touches nothing but the site's nginx `server_name`:
//!
//! - no certificate SAN, no Caddy route, no resolver route, no TLD policy;
//! - unique across every hostname rexenv knows (primaries, extra domains, the
//!   console vhosts and other public aliases), so one name reaches one site;
//! - removed with `--remove-alias` and when the site is deleted;
//! - re-read by every config rebuild, so it survives a regenerate and a
//!   restart.
//!
//! Stored in `public-aliases.json` beside `nginx.conf`, not in the database:
//! a schema step would make a stock build refuse this database (it refuses a
//! newer `user_version`), and rolling back to stock must stay possible. A
//! stock build ignores the file, so the aliases simply stop being served.

use crate::error::{Error, Result};
use crate::platform::traits::Platform;
use crate::state::store;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Site id → that site's public aliases (sorted).
pub type Map = HashMap<String, Vec<String>>;

const FILE: &str = "public-aliases.json";

fn path(platform: &dyn Platform) -> Result<PathBuf> {
    Ok(platform.paths().config_dir()?.join(FILE))
}

/// Every recorded public alias. A missing file is an empty map.
pub fn load(platform: &dyn Platform) -> Result<Map> {
    match std::fs::read_to_string(path(platform)?) {
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| Error::Other(format!("{FILE} is not valid: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(e) => Err(e.into()),
    }
}

fn save(platform: &dyn Platform, map: &Map) -> Result<()> {
    let dest = path(platform)?;
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(map)
        .map_err(|e| Error::Other(format!("cannot encode {FILE}: {e}")))?;
    // Write then rename, so a crash never leaves half a file for the next rebuild.
    let tmp = dest.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(())
}

/// The normalised host, or why it cannot be one. Hostname syntax only: no TLD
/// policy (that is the point), no wildcard, no IP-like single label.
pub fn validate_host(host: &str) -> Result<String> {
    let host = crate::core::sites::normalize_hostname(host);
    let bad = |why: &str| Err(Error::Other(format!("\"{host}\" can't be a public alias: {why}")));
    if host.is_empty() || host.len() > 253 {
        return bad("a hostname is 1 to 253 characters");
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return bad("it needs at least two labels (name.tld)");
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return bad("each label is 1 to 63 characters");
        }
        if !l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return bad("only letters, digits and hyphens");
        }
        if l.starts_with('-') || l.ends_with('-') {
            return bad("a label can't start or end with a hyphen");
        }
    }
    if labels.last().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())) {
        return bad("the last label can't be all digits");
    }
    Ok(host)
}

/// Is `host` taken by anything rexenv already serves, other than `site_id`'s
/// own public aliases? Returns the refusal.
fn taken(conn: &Connection, map: &Map, site_id: &str, host: &str) -> Result<Option<String>> {
    if host == crate::core::adminer::ADMINER_HOST || host == crate::core::phpmyadmin::PHPMYADMIN_HOST {
        return Ok(Some(format!("\"{host}\" is one of rexenv's own console names")));
    }
    if let Some(other) = store::site_by_domain(conn, host)? {
        return Ok(Some(format!("\"{host}\" is already the domain of the site \"{}\"", other.name)));
    }
    if let Some(owner) = store::site_id_for_alias(conn, host)? {
        return Ok(Some(format!("\"{host}\" is already an extra domain of site id {owner}")));
    }
    for (owner, hosts) in map {
        if owner != site_id && hosts.iter().any(|h| h == host) {
            return Ok(Some(format!("\"{host}\" is already a public alias of site id {owner}")));
        }
    }
    Ok(None)
}

/// Record a public alias for a site. Idempotent for the same site.
pub fn add(platform: &dyn Platform, conn: &Connection, site_id: &str, host: &str) -> Result<Vec<String>> {
    let host = validate_host(host)?;
    let live: HashSet<String> = crate::core::sites::list(conn)?.into_iter().map(|s| s.id).collect();
    if !live.contains(site_id) {
        return Err(Error::Other(format!("site not found: {site_id}")));
    }
    let mut map = load(platform)?;
    // Entries of deleted sites hold no name.
    map.retain(|id, _| live.contains(id));
    if let Some(why) = taken(conn, &map, site_id, &host)? {
        return Err(Error::Other(format!("{why} — one hostname can only reach one site")));
    }
    let hosts = map.entry(site_id.to_string()).or_default();
    if !hosts.contains(&host) {
        hosts.push(host);
        hosts.sort();
    }
    let out = hosts.clone();
    save(platform, &map)?;
    Ok(out)
}

/// Remove one public alias. Not an error when the site did not have it, so a
/// retry after a failed reload is safe.
pub fn remove(platform: &dyn Platform, site_id: &str, host: &str) -> Result<Vec<String>> {
    let host = crate::core::sites::normalize_hostname(host);
    let mut map = load(platform)?;
    if let Some(hosts) = map.get_mut(site_id) {
        hosts.retain(|h| *h != host);
        if hosts.is_empty() {
            map.remove(site_id);
        }
        save(platform, &map)?;
    }
    Ok(map.get(site_id).cloned().unwrap_or_default())
}

/// Forget every public alias of a deleted site.
pub fn forget_site(platform: &dyn Platform, site_id: &str) -> Result<()> {
    let mut map = load(platform)?;
    if map.remove(site_id).is_some() {
        save(platform, &map)?;
    }
    Ok(())
}

/// One site's public aliases.
pub fn for_site(platform: &dyn Platform, site_id: &str) -> Result<Vec<String>> {
    Ok(load(platform)?.remove(site_id).unwrap_or_default())
}

/// The alias map the NGINX config is built from: the extra domains plus the
/// public aliases of sites that exist. A public alias that collides with any
/// other name (a primary, an extra domain, an earlier public alias) is left
/// out and logged, never served twice. The edge and certificates keep using
/// the extra domains alone.
pub fn merged_for_nginx(sites: &[(&str, &str)], aliases: &HashMap<String, Vec<String>>, public: &Map) -> HashMap<String, Vec<String>> {
    let mut taken: HashSet<String> = sites.iter().map(|(_, d)| d.to_string()).collect();
    taken.extend(aliases.values().flatten().cloned());
    taken.insert(crate::core::adminer::ADMINER_HOST.to_string());
    taken.insert(crate::core::phpmyadmin::PHPMYADMIN_HOST.to_string());
    let mut out = aliases.clone();
    for (id, _) in sites {
        for host in public.get(*id).into_iter().flatten() {
            if taken.insert(host.clone()) {
                out.entry(id.to_string()).or_default().push(host.clone());
            } else {
                log::warn!("public alias {host} of site {id} collides with another name; not served");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_alias_may_use_any_real_tld() {
        assert_eq!(validate_host("WP-Demo.xspeedcdn.online.").unwrap(), "wp-demo.xspeedcdn.online");
        assert!(validate_host("shop.com").is_ok());
    }

    #[test]
    fn a_public_alias_is_still_a_hostname() {
        for bad in ["", "online", "*.x.online", "a..b", "-a.b", "a_b.c", "x.123"] {
            assert!(validate_host(bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn nginx_gets_public_aliases_of_live_sites_and_never_a_taken_name() {
        let sites = [("a", "a.rex"), ("b", "b.rex")];
        let aliases: HashMap<String, Vec<String>> = [("b".to_string(), vec!["shop.test".to_string()])].into();
        let public: Map = [
            ("a".to_string(), vec!["wp-a.example.online".to_string(), "shop.test".to_string(), "b.rex".to_string()]),
            ("gone".to_string(), vec!["wp-gone.example.online".to_string()]),
        ]
        .into();
        let out = merged_for_nginx(&sites, &aliases, &public);
        assert_eq!(out["a"], vec!["wp-a.example.online"]);
        assert_eq!(out["b"], vec!["shop.test"]);
        assert!(!out.contains_key("gone"));
    }
}
