use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrawlTarget {
    pub url: Url,
    pub depth: u32,
    pub score: u32,
    pub source: Option<Url>,
    pub is_form_action: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: ParamType,
    pub location: ParamLocation,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParamType {
    Query,
    FormInput,
    Cookie,
    Header,
    PathFragment,
    Json,
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParamLocation {
    Url,
    Body,
    Header,
    Cookie,
    Path,
    JsonBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlResult {
    pub url: Url,
    pub status_code: u16,
    pub links: HashSet<(Url, bool)>,
    pub parameters: Vec<Parameter>,
    pub forms: Vec<FormInfo>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

impl CrawlTarget {
    pub fn new(url: Url, depth: u32, source: Option<Url>, is_form_action: bool) -> Self {
        Self {
            url,
            depth,
            score: 0,
            source,
            is_form_action,
        }
    }
}
