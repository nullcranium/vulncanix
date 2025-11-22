use crate::crawler::types::{
    CrawlResult, CrawlTarget, FormInfo, ParamLocation, ParamType, Parameter,
};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

use regex::Regex;

pub struct PageProcessor {
    client: Client,
    url_regex: Regex,
}

impl PageProcessor {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            url_regex: Regex::new(r#"(?:https?://|/)[a-zA-Z0-9\./\?=&_\-]+"#).unwrap(),
        }
    }

    pub async fn process(&self, target: &CrawlTarget) -> Result<CrawlResult, reqwest::Error> {
        let response = self.client.get(target.url.clone()).send().await?;
        let status_code = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut links = HashSet::new();
        let mut parameters = Vec::new();
        let mut forms = Vec::new();

        // extract params from url
        for (key, value) in target.url.query_pairs() {
            parameters.push(Parameter {
                name: key.to_string(),
                param_type: ParamType::Query,
                location: ParamLocation::Url,
                value: Some(value.to_string()),
            });
        }

        if let Some(ct) = &content_type {
            let body = response.text().await?;
            let (extracted_links, extracted_params, extracted_forms) =
                self.extract_data(&body, ct, &target.url);

            links.extend(extracted_links);
            parameters.extend(extracted_params);
            forms.extend(extracted_forms);
        }

        Ok(CrawlResult {
            url: target.url.clone(),
            status_code,
            links,
            parameters,
            forms,
            content_type,
        })
    }

    pub fn extract_data(
        &self,
        body: &str,
        content_type: &str,
        base_url: &Url,
    ) -> (HashSet<(Url, bool)>, Vec<Parameter>, Vec<FormInfo>) {
        let mut links = HashSet::new();
        let mut parameters = Vec::new();
        let mut forms = Vec::new();

        if content_type.contains("text/html")
            || content_type.contains("application/javascript")
            || content_type.contains("application/json")
        {
            for cap in self.url_regex.captures_iter(body) {
                if let Some(m) = cap.get(0) {
                    if let Ok(url) = base_url.join(m.as_str()) {
                        links.insert((url, false));
                    }
                }
            }

            if content_type.contains("text/html") {
                let document = Html::parse_document(body);

                // extract links from <a> tags
                let link_selector = Selector::parse("a[href]").unwrap();
                for element in document.select(&link_selector) {
                    if let Some(href) = element.value().attr("href") {
                        if let Ok(url) = base_url.join(href) {
                            links.insert((url, false));
                        }
                    }
                }

                // extract scripts
                let script_selector = Selector::parse("script[src]").unwrap();
                for element in document.select(&script_selector) {
                    if let Some(src) = element.value().attr("src") {
                        if let Ok(url) = base_url.join(src) {
                            links.insert((url, false));
                        }
                    }
                }

                // extract forms
                let form_selector = Selector::parse("form").unwrap();
                let input_selector = Selector::parse("input, textarea, select").unwrap();

                for form in document.select(&form_selector) {
                    let action = form.value().attr("action").unwrap_or("");
                    let method = form.value().attr("method").unwrap_or("GET");

                    let mut inputs = Vec::new();
                    for input in form.select(&input_selector) {
                        if let Some(name) = input.value().attr("name") {
                            inputs.push(name.to_string());
                            parameters.push(Parameter {
                                name: name.to_string(),
                                param_type: ParamType::FormInput,
                                location: ParamLocation::Body,
                                value: input.value().attr("value").map(|v| v.to_string()),
                            });
                        }
                    }

                    forms.push(FormInfo {
                        action: action.to_string(),
                        method: method.to_string(),
                        inputs,
                    });

                    // add form action to links with is_form_action=true
                    if !action.is_empty() {
                        if let Ok(url) = base_url.join(action) {
                            links.insert((url, true));
                        }
                    }
                }
            } else if content_type.contains("application/json") {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(obj) = json.as_object() {
                        for (key, value) in obj {
                            parameters.push(Parameter {
                                name: key.clone(),
                                param_type: ParamType::Json,
                                location: ParamLocation::JsonBody,
                                value: Some(value.to_string()),
                            });
                        }
                    }
                }
            }

            let path = base_url.path();
            let id_regex = Regex::new(r"/\d+(?:/|$)").unwrap();
            if id_regex.is_match(path) {
                parameters.push(Parameter {
                    name: "id".to_string(),
                    param_type: ParamType::PathFragment,
                    location: ParamLocation::Path,
                    value: None,
                });
            }

            let uuid_regex = Regex::new(r"/[a-f0-9-]{36}(?:/|$)").unwrap();
            if uuid_regex.is_match(path) {
                parameters.push(Parameter {
                    name: "uuid".to_string(),
                    param_type: ParamType::PathFragment,
                    location: ParamLocation::Path,
                    value: None,
                });
            }

            let heuristic_params = crate::crawler::endpoints::get_heuristic_parameters(path);
            parameters.extend(heuristic_params);

            if content_type.contains("application/javascript") || content_type.contains("text/html")
            {
                // look for fetch('...') or fetch("...")
                let fetch_regex = Regex::new(r#"fetch\(['"]([^'"]+)['"]\)"#).unwrap();
                for cap in fetch_regex.captures_iter(body) {
                    if let Some(m) = cap.get(1) {
                        if let Ok(url) = base_url.join(m.as_str()) {
                            links.insert((url, false));
                        }
                    }
                }
            }
        }

        (links, parameters, forms)
    }
    pub fn extract_urls_from_text(&self, text: &str) -> HashSet<String> {
        let mut urls = HashSet::new();
        for cap in self.url_regex.captures_iter(text) {
            if let Some(m) = cap.get(0) {
                urls.insert(m.as_str().to_string());
            }
        }

        let fetch_regex = Regex::new(r#"fetch\(['"]([^'"]+)['"]\)"#).unwrap();
        for cap in fetch_regex.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                urls.insert(m.as_str().to_string());
            }
        }

        urls
    }
}
