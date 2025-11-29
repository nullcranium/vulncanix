use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
    pub response_time: u128,
    pub content_hash: String,
    pub server_header: Option<String>,
    pub header_loc: Option<String>,
    pub content_type: Option<String>,
    pub body_preview: String,
}

pub struct HttpClient {
    client: Client,
    target_url: Url,
}

impl HttpClient {
    pub fn new(
        target_url: &str,
        timeout: u64,
        user_agent: &str,
        follow_redirects: bool,
        insecure: bool,
        verbose: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let redirect_policy = if follow_redirects {
            Policy::limited(10)
        } else {
            Policy::none()
        };

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(timeout))
            .user_agent(user_agent)
            .redirect(redirect_policy);

        // add "SSL cert bypass" if insecure flag is set
        if insecure {
            client_builder = client_builder.danger_accept_invalid_certs(true);

            if verbose {
                eprintln!("SSL certificate verification disabled!");
            }
        }

        let client = client_builder.build()?;
        let target_url = Url::parse(target_url)?;

        Ok(Self { client, target_url })
    }

    pub async fn make_request(
        &self,
        path: &str,
    ) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.target_url.join(path)?;
        let start_time = Instant::now();

        let response = self.client.get(url.clone()).send().await?;
        let response_time = start_time.elapsed().as_millis();

        let status_code = response.status().as_u16();
        let content_length = response.content_length().unwrap_or(0) as usize;

        let server_header = response
            .headers()
            .get("server")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let header_loc = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let content = response.text().await?;
        let content_hash = self.hash_content(&content);
        let body_preview = content.chars().take(1024).collect::<String>();
        Ok(ScanResult {
            url: url.to_string(),
            status_code,
            content_length,
            response_time,
            content_hash,
            server_header,
            header_loc,
            content_type,
            body_preview,
        })
    }

    fn hash_content(&self, content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
