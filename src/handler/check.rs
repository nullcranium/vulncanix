use crate::handler::http_client::ScanResult;

pub struct ResponseAnalyzer {
    hashes_404: Vec<String>,
    avg_response_time: u128,
    safe_config_files: Vec<String>,
}

impl ResponseAnalyzer {
    pub fn new() -> Self {
        Self {
            hashes_404: Vec::new(),
            avg_response_time: 0,
            safe_config_files: vec![
                ".editorconfig".to_string(),
                ".prettierrc".to_string(),
                ".eslintrc".to_string(),
                ".gitignore".to_string(),
                ".dockerignore".to_string(),
                ".npmignore".to_string(),
                ".babelrc".to_string(),
                ".stylelintrc".to_string(),
                "tsconfig.json".to_string(),
                "package.json".to_string(),
                "composer.json".to_string(),
                ".htaccess".to_string(),
                "robots.txt".to_string(),
                "sitemap.xml".to_string(),
            ],
        }
    }

    pub fn store_404_hashes(&mut self, hash: String) {
        self.hashes_404.push(hash);
    }

    pub fn set_avg_response_time(&mut self, time: u128) {
        self.avg_response_time = time;
    }

    pub fn is_interesting(&self, result: &ScanResult) -> bool {
        if self.hashes_404.contains(&result.content_hash) {
            return false;
        }
        if self.is_error_page(result) {
            return false;
        }

        match result.status_code {
            200..=299 => true,
            300..=399 => true,
            401 => true,
            403 => true,
            500..=599 => true,
            _ => false,
        }
    }

    fn is_error_page(&self, result: &ScanResult) -> bool {
        let body_lower = result.body_preview.to_lowercase();
        let error_indicators = [
            "error 404",
            "error 500",
            "not found",
            "page not found",
            "tidak tersedia",
            "halaman tidak tersedia",
            "tidak ditemukan",
            "halaman tidak ditemukan",
            "unavailable",
            "page unavailable",
            "access denied",
            "forbidden",
            "internal server error",
            "something went wrong",
            "terjadi kesalahan",
        ];

        for indicator in &error_indicators {
            if body_lower.contains(indicator) {
                return true;
            }
        }

        if result.status_code >= 500 && result.status_code < 600 {
            if result.content_length < 500 {
                return true;
            }
            if body_lower.contains("500")
                && (body_lower.contains("error")
                    || body_lower.contains("tidak")
                    || body_lower.contains("tersedia")
                    || body_lower.contains("internal server"))
            {
                return true;
            }
        }

        if result.status_code == 200 {
            if body_lower.contains("error")
                && (body_lower.contains("404")
                    || body_lower.contains("500")
                    || body_lower.contains("403")
                    || body_lower.contains("502")
                    || body_lower.contains("503"))
            {
                return true;
            }
        }

        false
    }

    fn is_safe_config_file(&self, url: &str) -> bool {
        self.safe_config_files
            .iter()
            .any(|safe_file| url.ends_with(safe_file) || url.contains(&format!("/{}", safe_file)))
    }

    pub fn get_vuln_indicators(&self, result: &ScanResult) -> Vec<String> {
        let mut indicators = Vec::new();

        match result.status_code {
            401 => indicators.push("Authentication Required".to_string()),
            403 => indicators.push("Access Forbidden".to_string()),
            500..=599 => indicators.push("Server Error".to_string()),
            _ => {}
        }

        if result.url.contains(".bak")
            || result.url.contains(".backup")
            || result.url.contains(".old")
            || result.url.contains("~")
        {
            indicators.push("Backup File".to_string());
        }

        if result.url.contains("admin") || result.url.contains("login") {
            indicators.push("Admin Interface".to_string());
        }

        if (result.url.contains("config") || result.url.contains(".env"))
            && !self.is_safe_config_file(&result.url)
        {
            indicators.push("Configuration File".to_string());
        }

        indicators
    }

    pub fn get_risk_score(&self, result: &ScanResult) -> u8 {
        let mut score = 0;

        if self.is_safe_config_file(&result.url) {
            return 2;
        }

        // score priority
        score += match result.status_code {
            200..=299 => 5,
            401 => 8,
            403 => 7,
            500..=599 => 6,
            _ => 1,
        };

        if result.url.contains("admin") || result.url.contains("login") {
            score += 3;
        }

        if (result.url.contains("config") || result.url.contains(".env"))
            && !self.is_safe_config_file(&result.url)
        {
            score += 4;
        }

        if result.url.contains(".bak") || result.url.contains(".backup") {
            score += 2;
        }

        score.min(10)
    }
}
