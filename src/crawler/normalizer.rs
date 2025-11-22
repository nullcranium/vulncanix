/// url normalizer to prevent duplicate URLs from being crawled
/// this ensures stable and efficient crawling by canonicalizing URLs
use std::collections::BTreeMap;
use url::Url;
pub struct UrlNormalizer;

impl UrlNormalizer {
    pub fn normalize(url: &Url) -> String {
        let mut normalized = String::new();

        normalized.push_str(&url.scheme().to_lowercase());
        normalized.push_str("://");

        if let Some(host) = url.host_str() {
            normalized.push_str(&host.to_lowercase());
        }

        if let Some(port) = url.port() {
            let default_port = match url.scheme() {
                "http" => 80,
                "https" => 443,
                _ => 0,
            };
            if port != default_port {
                normalized.push(':');
                normalized.push_str(&port.to_string());
            }
        }

        let path = url.path();
        let normalized_path = Self::normalize_path(path);
        normalized.push_str(&normalized_path);
        if let Some(query) = url.query() {
            let sorted_query = Self::normalize_query(query);
            if !sorted_query.is_empty() {
                normalized.push('?');
                normalized.push_str(&sorted_query);
            }
        }
        normalized
    }

    // normalize path by removing redundant slashes
    // and resolving . and ..
    fn normalize_path(path: &str) -> String {
        if path.is_empty() {
            return "/".to_string();
        }

        let mut segments = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {
                    continue;
                }
                ".." => {
                    segments.pop();
                }
                _ => {
                    segments.push(segment);
                }
            }
        }

        let mut result = String::from("/");
        for (i, segment) in segments.iter().enumerate() {
            if i > 0 {
                result.push('/');
            }
            result.push_str(segment);
        }

        if path.len() > 1 && path.ends_with('/') && !result.ends_with('/') {
            result.push('/');
        }

        result
    }

    fn normalize_query(query: &str) -> String {
        let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");

            params
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }

        let mut result = Vec::new();
        for (key, values) in params {
            for value in values {
                if value.is_empty() {
                    result.push(key.clone());
                } else {
                    result.push(format!("{}={}", key, value));
                }
            }
        }

        result.join("&")
    }

    pub fn are_equivalent(url1: &Url, url2: &Url) -> bool {
        Self::normalize(url1) == Self::normalize(url2)
    }

    // generate a fingerprint for parameter-based deduplication
    // this creates a signature that ignores param VALUES but keeps structure
    pub fn parameter_fingerprint(url: &Url) -> String {
        let mut fingerprint = String::new();

        fingerprint.push_str(&url.scheme().to_lowercase());
        fingerprint.push_str("://");

        if let Some(host) = url.host_str() {
            fingerprint.push_str(&host.to_lowercase());
        }

        fingerprint.push_str(&Self::normalize_path(url.path()));

        if let Some(query) = url.query() {
            let mut param_names: Vec<String> = query
                .split('&')
                .filter_map(|pair| {
                    let key = pair.split('=').next()?;
                    if !key.is_empty() {
                        Some(key.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            param_names.sort();
            param_names.dedup();

            if !param_names.is_empty() {
                fingerprint.push('?');
                fingerprint.push_str(&param_names.join("&"));
            }
        }

        fingerprint
    }
}
