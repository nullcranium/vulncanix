use crate::config::Config;
use crate::handler::http_client::ScanResult;
use crate::scanner::autoscan::WebScanner;
use crate::wordlist::WordlistLoader;
use clap::Parser;
use colored::*;
use serde_json;
use std::process;
use std::thread;
use std::time::Duration;

mod config;
pub mod crawler;
mod handler;
mod scanner;
mod wordlist;

fn print_banner() {
    let banner = r#"
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗ █████╗ ███╗   ██╗██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗████╗  ██║██║╚██╗██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ███████║██╔██╗ ██║██║ ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══██║██║╚██╗██║██║ ██╔██╗ 
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║ ╚████║██║██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
    "#;
    println!("{}", banner.bright_cyan().bold());
    println!(
        "{}",
        "         Web Vulnerability Scanner & Smart Crawler v1.1"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "         https://github.com/nullcranium/vulncanix".dimmed()
    );
    println!();
}

pub struct OutputFormatter {
    output_format: String,
    colors_enabled: bool,
}

impl OutputFormatter {
    pub fn new(fmt: &str) -> Self {
        Self {
            output_format: fmt.to_string(),
            colors_enabled: atty::is(atty::Stream::Stdout),
        }
    }

    pub fn display_result(
        &self,
        scan_result: &ScanResult,
        warning_flags: &[String],
        danger_level: u8,
    ) {
        match self.output_format.as_str() {
            "json" => self.print_json(scan_result, warning_flags, danger_level),
            _ => self.print_result(scan_result, warning_flags, danger_level),
        }
    }

    fn print_result(&self, scan_result: &ScanResult, warning_flags: &[String], danger_level: u8) {
        let (status_display, status_icon) = if self.colors_enabled {
            let icon = match scan_result.status_code {
                200..=299 => "✓".green(),
                300..=399 => "→".yellow(),
                400..=499 => "✗".red(),
                500..=599 => "!".magenta(),
                _ => "?".white(),
            };
            (self.colorize_status(scan_result.status_code), icon)
        } else {
            (scan_result.status_code.to_string(), "•".white())
        };

        let size_info = if scan_result.content_length > 0 {
            if self.colors_enabled {
                format!(
                    "({})",
                    format!("{} bytes", scan_result.content_length).dimmed()
                )
            } else {
                format!("({} bytes)", scan_result.content_length)
            }
        } else {
            String::new()
        };

        let redirect_info = if let Some(ref redir_location) = scan_result.header_loc {
            if self.colors_enabled {
                format!(" {} {}", "→".cyan(), redir_location.bright_blue())
            } else {
                format!(" -> {}", redir_location)
            }
        } else {
            String::new()
        };

        print!(
            "{} {} {} {}{}",
            status_icon, status_display, scan_result.url, size_info, redirect_info
        );

        if !warning_flags.is_empty() {
            if self.colors_enabled {
                print!(
                    " {}",
                    format!("[{}]", warning_flags.join(", ")).yellow().bold()
                );
            } else {
                print!(" [{}]", warning_flags.join(", "));
            }
        }

        if danger_level > 7 {
            if self.colors_enabled {
                print!(" {}", "[CRITICAL]".red().bold());
            } else {
                print!(" [CRITICAL]");
            }
        } else if danger_level > 5 {
            if self.colors_enabled {
                print!(" {}", "[ELEVATED]".yellow().bold());
            } else {
                print!(" [ELEVATED]");
            }
        }

        println!();
    }

    fn print_json(&self, scan_result: &ScanResult, warning_flags: &[String], danger_level: u8) {
        let json_output = serde_json::json!({
            "url": scan_result.url,
            "status_code": scan_result.status_code,
            "content_length": scan_result.content_length,
            "response_time": scan_result.response_time,
            "server": scan_result.server_header,
            "location": scan_result.header_loc,
            "content_type": scan_result.content_type,
            "indicators": warning_flags,
            "risk_score": danger_level
        });

        println!("{}", json_output);
    }

    fn colorize_status(&self, status_num: u16) -> String {
        match status_num {
            200..=299 => status_num.to_string().green().to_string(),
            300..=399 => status_num.to_string().yellow().to_string(),
            400..=499 => status_num.to_string().red().to_string(),
            500..=599 => status_num.to_string().magenta().to_string(),
            _ => status_num.to_string().white().to_string(),
        }
    }

    pub fn show_summary(&self, total_reqs: usize, interesting_hits: usize, time_taken: u128) {
        println!();
        if self.colors_enabled {
            println!(
                "{}",
                "╔═══════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║           Scan Complete - Summary             ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╠═══════════════════════════════════════════════╣".cyan()
            );
            println!(
                "{} {} {}",
                "║".cyan(),
                format!(
                    "Total Requests      : {}",
                    total_reqs.to_string().bright_white().bold()
                ),
                "║".cyan()
            );
            println!(
                "{} {} {}",
                "║".cyan(),
                format!(
                    "Interesting Finds   : {}",
                    interesting_hits.to_string().green().bold()
                ),
                "║".cyan()
            );
            println!(
                "{} {} {}",
                "║".cyan(),
                format!(
                    "Time Elapsed        : {}ms",
                    time_taken.to_string().yellow()
                ),
                "║".cyan()
            );
            let rps = total_reqs as f64 / (time_taken as f64 / 1000.0);
            println!(
                "{} {} {}",
                "║".cyan(),
                format!("Requests/Second     : {:.2}", rps).bright_magenta(),
                "║".cyan()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════╝".cyan()
            );
        } else {
            println!("===============================================");
            println!("Scan Summary:");
            println!("Total requests        : {}", total_reqs);
            println!("Interesting responses : {}", interesting_hits);
            println!("Elapsed time          : {}ms", time_taken);
            println!(
                "Requests per second   : {:.2}",
                total_reqs as f64 / (time_taken as f64 / 1000.0)
            );
            println!("===============================================");
        }
    }
}

#[tokio::main]
async fn main() {
    let cli_args = Config::parse();

    print_banner();
    thread::sleep(Duration::from_millis(100));

    println!("{}", "Configuration:".bright_yellow().bold());
    thread::sleep(Duration::from_millis(50));
    println!(
        "  {} {}",
        "✓".green(),
        format!("Target: {}", cli_args.target.bright_white())
    );
    thread::sleep(Duration::from_millis(50));
    println!(
        "  {} {}",
        "✓".green(),
        format!(
            "Concurrency: {}",
            cli_args.concurrency.to_string().bright_white()
        )
    );
    thread::sleep(Duration::from_millis(50));
    println!(
        "  {} {}",
        "✓".green(),
        format!("Timeout: {}s", cli_args.timeout.to_string().bright_white())
    );
    thread::sleep(Duration::from_millis(50));

    println!();
    println!("{}", "Initializing scanner...".bright_yellow().bold());
    thread::sleep(Duration::from_millis(100));

    let dict_loader = WordlistLoader::new();
    let word_list = match dict_loader.load(&cli_args.wordlist).await {
        Ok(words) => words,
        Err(e) => {
            eprintln!(
                "{} {}",
                "✗".red().bold(),
                format!("Failed to load wordlist: {}", e).red()
            );
            process::exit(1);
        }
    };

    println!(
        "  {} {}",
        "✓".green(),
        format!(
            "Loaded {} entries from wordlist",
            word_list.len().to_string().bright_white().bold()
        )
    );
    thread::sleep(Duration::from_millis(100));
    println!();
    println!("{}", "═".repeat(60).cyan());
    println!("{}", "Starting scan...".bright_green().bold());
    println!("{}", "═".repeat(60).cyan());
    thread::sleep(Duration::from_millis(100));

    let vulnerability_scanner =
        match WebScanner::new(&cli_args.target, cli_args.concurrency, cli_args.timeout) {
            Ok(scanner) => scanner,
            Err(e) => {
                eprintln!(
                    "{} {}",
                    "✗".red().bold(),
                    format!("Failed to initialize scanner: {}", e).red()
                );
                process::exit(1);
            }
        };

    if cli_args.crawl {
        println!();
        if cli_args.hybrid {
            println!("{}", "Hybrid Mode Activated".bright_magenta().bold());
            println!("{}", "  (Crawler Discovery + Wordlist Scanning)".dimmed());
        } else {
            println!("{}", "Crawler Mode Activated".bright_magenta().bold());
        }

        thread::sleep(Duration::from_millis(80));
        println!(
            "  {} {}",
            "✓".green(),
            format!("Target: {}", cli_args.target.bright_white())
        );
        thread::sleep(Duration::from_millis(50));
        println!(
            "  {} {}",
            "✓".green(),
            format!("Max Depth: {}", cli_args.depth.to_string().bright_white())
        );
        thread::sleep(Duration::from_millis(50));
        println!(
            "  {} {}",
            "✓".green(),
            format!(
                "Max Pages: {}",
                cli_args.max_pages.to_string().bright_white()
            )
        );
        thread::sleep(Duration::from_millis(50));
        println!("{}", "═".repeat(60).cyan());

        let seed_url = match url::Url::parse(&cli_args.target) {
            Ok(url) => url,
            Err(e) => {
                eprintln!(
                    "{} {}",
                    "✗".red().bold(),
                    format!("Invalid target URL: {}", e).red()
                );
                process::exit(1);
            }
        };

        let mut engine = crate::crawler::engine::CrawlerEngine::new(
            seed_url,
            cli_args.depth,
            cli_args.max_pages,
            cli_args.allow_external,
        );
        let crawl_results = engine.run().await;

        println!();
        println!("{}", "═".repeat(60).cyan());
        println!(
            "{} {}",
            "✓".green().bold(),
            format!(
                "Crawl complete! Discovered {} pages",
                crawl_results.len().to_string().bright_white().bold()
            )
            .green()
        );

        // if hybrid mode, extract base paths
        // and run wordlist scanning
        if cli_args.hybrid {
            println!();
            println!("{}", "═".repeat(60).cyan());
            println!("{}", "Phase 2: Wordlist Scanning".bright_cyan().bold());
            thread::sleep(Duration::from_millis(100));

            let mut base_paths = std::collections::HashSet::new();
            for result in &crawl_results {
                let url_str = result.url.to_string();
                if let Some(last_slash_idx) = url_str.rfind('/') {
                    if last_slash_idx > 8 {
                        let base = &url_str[..last_slash_idx + 1];
                        base_paths.insert(base.to_string());
                    }
                }
            }

            println!(
                "  {} {}",
                "✓".green(),
                format!(
                    "Extracted {} unique base paths from crawled URLs",
                    base_paths.len().to_string().bright_white().bold()
                )
                .green()
            );
            thread::sleep(Duration::from_millis(80));

            println!();
            println!(
                "{}",
                "Starting wordlist scans on discovered paths...".bright_yellow()
            );
            thread::sleep(Duration::from_millis(100));

            for (idx, base_path) in base_paths.iter().enumerate() {
                println!();
                println!(
                    "{} {} {}",
                    "→".cyan(),
                    format!("Scanning base path ({}/{})", idx + 1, base_paths.len()).dimmed(),
                    base_path.bright_white()
                );

                let scan_start = std::time::Instant::now();
                match WebScanner::new(base_path, cli_args.concurrency, cli_args.timeout) {
                    Ok(scanner) => {
                        if let Ok(()) = scanner.run_scan(word_list.clone()).await {
                            // results are printed by run_scan
                        }

                        let scan_duration = scan_start.elapsed().as_secs();
                        println!(
                            "  {} {}",
                            "✓".green(),
                            format!("Completed in {}s", scan_duration.to_string().dimmed())
                                .dimmed()
                        );
                    }
                    Err(e) => {
                        if cli_args.verbose {
                            eprintln!("  {} Failed to scan {}: {}", "✗".red(), base_path, e);
                        }
                    }
                }
            }

            println!();
            println!("{}", "═".repeat(60).cyan());
            println!("{}", "✓ Hybrid scan complete!".green().bold());
            println!(
                "  {} Crawled {} pages",
                "→".cyan(),
                crawl_results.len().to_string().bright_white()
            );
            println!(
                "  {} Scanned {} base paths with wordlist",
                "→".cyan(),
                base_paths.len().to_string().bright_white()
            );

            return;
        }
        if cli_args.output == "json" {
            let json_output = serde_json::json!(crawl_results);
            println!("{}", json_output);
        } else {
            for result in crawl_results {
                let status_color = match result.status_code {
                    200..=299 => result.status_code.to_string().green(),
                    300..=399 => result.status_code.to_string().yellow(),
                    _ => result.status_code.to_string().red(),
                };
                println!(
                    "  {} {} {}",
                    "•".cyan(),
                    result.url.to_string().bright_white(),
                    format!("({})", status_color)
                );
                for param in result.parameters {
                    println!(
                        "    {} {} {}",
                        "→".dimmed(),
                        param.name.bright_yellow(),
                        format!("({:?})", param.param_type).dimmed()
                    );
                }
            }
        }
        return;
    }

    if let Err(e) = vulnerability_scanner.run_scan(word_list).await {
        eprintln!(
            "{} {}",
            "✗".red().bold(),
            format!("Scan failed: {}", e).red()
        );
        process::exit(1);
    }

    println!();
    println!(
        "{}",
        "✓ All operations completed successfully".green().bold()
    );
}
