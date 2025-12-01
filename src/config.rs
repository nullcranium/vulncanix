use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    // target url
    #[arg(short, long)]
    pub target: String,

    // num of concurrent requests
    #[arg(short, long, default_value = "10")]
    pub concurrency: usize,

    // rto in seconds
    #[arg(short = 'T', long, default_value = "10")]
    pub timeout: u64,

    // get wordlist
    // default, set to "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt"
    #[arg(
        short,
        long,
        default_value = "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt"
    )]
    pub wordlist: String,

    #[arg(short, long, default_value = "txt")]
    pub output: String,

    #[arg(long)]
    pub status_codes: Option<String>,

    #[arg(long)]
    pub hide_status_codes: Option<String>,

    // extensions to append to wordlist entries
    #[arg(short, long)]
    pub extensions: Option<String>,

    #[arg(long, default_value = "vulncanix/1.0")]
    pub user_agent: String,

    #[arg(long)]
    pub follow_redirects: bool,

    #[arg(short, long)]
    pub verbose: bool,

    // SSL certificate bypass option
    #[arg(
        short = 'k',
        long,
        help = "Skip SSL certificate verification (insecure)"
    )]
    pub insecure: bool,

    #[arg(long, help = "Enable crawler mode")]
    pub crawl: bool,

    #[arg(long, default_value = "3", help = "Max crawl depth")]
    pub depth: u32,

    #[arg(long, default_value = "100", help = "Max pages to crawl")]
    pub max_pages: usize,

    #[arg(long, help = "Allow crawling external domains")]
    pub allow_external: bool,

    #[arg(long, help = "Show progress bar during scanning")]
    pub bar: bool,

    #[arg(long, help = "Enable hybrid mode (crawler + wordlist scanning)")]
    pub hybrid: bool,
}

impl Config {
    pub fn get_status_codes_filter(&self) -> Option<Vec<u16>> {
        self.status_codes.as_ref().map(|codes| {
            codes
                .split(',')
                .filter_map(|code| code.trim().parse().ok())
                .collect()
        })
    }

    pub fn get_hide_status_codes(&self) -> Option<Vec<u16>> {
        self.hide_status_codes.as_ref().map(|codes| {
            codes
                .split(',')
                .filter_map(|code| code.trim().parse().ok())
                .collect()
        })
    }

    pub fn get_extensions(&self) -> Vec<String> {
        self.extensions
            .as_ref()
            .map(|ext| ext.split(',').map(|e| e.trim().to_string()).collect())
            .unwrap_or_default()
    }
}
