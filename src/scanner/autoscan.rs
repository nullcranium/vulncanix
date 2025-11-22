use crate::OutputFormatter;
use crate::config::Config;
use crate::handler::check::ResponseAnalyzer;
use crate::handler::http_client::{HttpClient, ScanResult};

use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

pub struct WebScanner {
    http_client: Arc<HttpClient>,
    semaphore: Arc<Semaphore>,
    analyzer: Arc<RwLock<ResponseAnalyzer>>,
    output_formatter: Arc<OutputFormatter>,
    config: Arc<Config>,
    results: Arc<RwLock<Vec<ScanResult>>>,
}

impl WebScanner {
    pub fn new(
        target: &str,
        concurrency: usize,
        timeout: u64,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = Config::parse();

        let http_client = Arc::new(HttpClient::new(
            target,
            timeout,
            &config.user_agent,
            config.follow_redirects,
            config.insecure,
            config.verbose,
        )?);

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let analyzer = Arc::new(RwLock::new(ResponseAnalyzer::new()));
        let output_formatter = Arc::new(OutputFormatter::new(&config.output));
        let config = Arc::new(config);

        Ok(Self {
            http_client,
            semaphore,
            analyzer,
            output_formatter,
            config,
            results: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn run_scan(
        &self,
        wordlist: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = Instant::now();

        self.fingerprint_server().await?;
        let expanded_wordlist = self.expand_wordlist(wordlist);

        // show progress bar only if '--bar' flag is set
        let progress = if self.config.bar {
            let pb = ProgressBar::new(expanded_wordlist.len() as u64);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                .unwrap()
                .progress_chars("█▓░"));
            pb
        } else {
            ProgressBar::hidden()
        };

        let mut handles = Vec::new();

        for path in expanded_wordlist {
            let http_client = self.http_client.clone();
            let semaphore = self.semaphore.clone();
            let analyzer = self.analyzer.clone();
            let output_formatter = self.output_formatter.clone();
            let config = self.config.clone();
            let results = self.results.clone();
            let progress_clone = progress.clone();

            let handle = tokio::spawn(async move {
                let scanner = ScannerTask {
                    http_client,
                    semaphore,
                    analyzer,
                    output_formatter,
                    config,
                    results,
                };

                scanner.scan_path(&path, &progress_clone).await;
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                eprintln!("[-] Task error: {}", e);
            }
        }

        if self.config.bar {
            progress.finish_with_message("✓ Scan complete");
        }

        // result
        let elapsed = start_time.elapsed().as_millis();
        let results = self.results.read().await;
        let interesting_count = results
            .iter()
            .filter(|r| {
                let analyzer = futures::executor::block_on(self.analyzer.read());
                analyzer.is_interesting(r)
            })
            .count();

        self.output_formatter
            .show_summary(results.len(), interesting_count, elapsed);

        Ok(())
    }

    async fn fingerprint_server(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("  {} {}", "→".cyan(), "Analyzing..".bright_yellow());
        thread::sleep(Duration::from_millis(100));

        let test_paths = vec![
            "/definitely-not-existing-path-12345",
            "/nonexistent-directory/test",
            "/random-file-name.html",
        ];

        let mut response_times = Vec::new();
        let mut analyzer = self.analyzer.write().await;

        for path in test_paths {
            if let Ok(result) = self.http_client.make_request(path).await {
                analyzer.store_404_hashes(result.content_hash);
                response_times.push(result.response_time);
            }
        }

        if !response_times.is_empty() {
            let avg_time = response_times.iter().sum::<u128>() / response_times.len() as u128;
            analyzer.set_avg_response_time(avg_time);
        }

        println!(
            "  {} {}",
            "✓".green(),
            "Server fingerprint complete".green()
        );
        thread::sleep(Duration::from_millis(80));
        Ok(())
    }

    fn expand_wordlist(&self, wordlist: Vec<String>) -> Vec<String> {
        let extensions = self.config.get_extensions();
        let mut expanded = Vec::new();

        for word in wordlist {
            // add original word
            expanded.push(word.clone());

            // add word with extensions
            for ext in &extensions {
                expanded.push(format!("{}.{}", word, ext));
            }

            // add dir version
            if !word.ends_with('/') {
                expanded.push(format!("{}/", word));
            }
        }

        println!(
            "  {} {}",
            "✓".green(),
            format!(
                "Expanded to {} test cases",
                expanded.len().to_string().bright_white().bold()
            )
            .green()
        );
        thread::sleep(Duration::from_millis(80));

        expanded
    }
}

struct ScannerTask {
    http_client: Arc<HttpClient>,
    semaphore: Arc<Semaphore>,
    analyzer: Arc<RwLock<ResponseAnalyzer>>,
    output_formatter: Arc<OutputFormatter>,
    config: Arc<Config>,
    results: Arc<RwLock<Vec<ScanResult>>>,
}

impl ScannerTask {
    async fn scan_path(&self, path: &str, progress: &ProgressBar) {
        let _permit = match self.semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                progress.inc(1);
                return;
            }
        };

        match self.http_client.make_request(path).await {
            Ok(result) => {
                let analyzer = self.analyzer.read().await;

                // check if we should display this result
                if self.should_display_result(&result, &analyzer) {
                    let indicators = analyzer.get_vuln_indicators(&result);
                    let risk_score = analyzer.get_risk_score(&result);

                    self.output_formatter
                        .print_result(&result, &indicators, risk_score);
                }

                self.results.write().await.push(result);
            }
            Err(e) => {
                if self.config.verbose {
                    eprintln!("[-] Error scanning {}: {}", path, e);
                }
            }
        }

        progress.inc(1);
    }

    fn should_display_result(&self, result: &ScanResult, analyzer: &ResponseAnalyzer) -> bool {
        if !analyzer.is_interesting(result) {
            return false;
        }

        if let Some(show_codes) = self.config.get_status_codes_filter().as_ref() {
            if !show_codes.contains(&result.status_code) {
                return false;
            }
        }

        if let Some(hide_codes) = self.config.get_hide_status_codes().as_ref() {
            if hide_codes.contains(&result.status_code) {
                return false;
            }
        }

        true
    }
}
