use crate::crawler::normalizer::UrlNormalizer;
use crate::crawler::processor::PageProcessor;
use crate::crawler::queue::PriorityUrlQueue;
use crate::crawler::types::{CrawlResult, CrawlTarget};
use colored::*;
use reqwest::Client;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use url::Url;

pub struct CrawlerEngine {
    queue: PriorityUrlQueue,
    visited: HashSet<String>,
    processor: PageProcessor,
    max_depth: u32,
    max_pages: usize,
    allow_external: bool,
    seed_domain: Option<String>,
}

impl CrawlerEngine {
    pub fn new(seed_url: Url, max_depth: u32, max_pages: usize, allow_external: bool) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Vulncanix/1.0")
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let mut queue = PriorityUrlQueue::new();
        queue.push(CrawlTarget::new(seed_url.clone(), 0, None, false));

        let seed_domain = seed_url.domain().map(|s| s.to_string());

        Self {
            queue,
            visited: HashSet::new(),
            processor: PageProcessor::new(client),
            max_depth,
            max_pages,
            allow_external,
            seed_domain,
        }
    }

    pub async fn run(&mut self) -> Vec<CrawlResult> {
        let mut results = Vec::new();

        while let Some(target) = self.queue.pop() {
            // duplicate detection
            let normalized_url = UrlNormalizer::normalize(&target.url);

            if self.visited.contains(&normalized_url) {
                continue;
            }

            if self.visited.len() >= self.max_pages {
                break;
            }

            let depth_indicator = "  ".repeat(target.depth as usize);
            let priority_color = if target.score > 70 {
                "HIGH".bright_red()
            } else if target.score > 40 {
                "MED".yellow()
            } else {
                "LOW".dimmed()
            };

            println!(
                "{}{}  {} {} {} {} {}",
                depth_indicator,
                "→".cyan(),
                priority_color,
                "Crawling:".dimmed(),
                target.url.to_string().bright_white(),
                format!("(depth: {})", target.depth).dimmed(),
                format!("(score: {})", target.score).dimmed()
            );
            thread::sleep(Duration::from_millis(50));
            self.visited.insert(normalized_url.clone());

            match self.processor.process(&target).await {
                Ok(result) => {
                    // add new links to queue
                    if target.depth < self.max_depth {
                        for (link, is_form_action) in &result.links {
                            // normalize link before checking if visited
                            let normalized_link = UrlNormalizer::normalize(link);

                            if !self.visited.contains(&normalized_link) {
                                // check same-domain policy
                                if !self.allow_external {
                                    if let Some(domain) = link.domain() {
                                        if let Some(seed_domain) = &self.seed_domain {
                                            if domain != seed_domain {
                                                continue;
                                            }
                                        }
                                    }
                                }

                                self.queue.push(CrawlTarget::new(
                                    link.clone(),
                                    target.depth + 1,
                                    Some(target.url.clone()),
                                    *is_form_action,
                                ));
                            }
                        }
                    }
                    results.push(result);
                }
                Err(e) => {
                    eprintln!(
                        "  {} {} {} {}",
                        "✗".red(),
                        "Error:".red().bold(),
                        target.url.to_string().dimmed(),
                        format!("({})", e).red().dimmed()
                    );
                }
            }
        }

        results
    }
}
