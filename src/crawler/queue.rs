use crate::crawler::types::CrawlTarget;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Debug)]
pub struct PriorityUrlQueue {
    heap: BinaryHeap<QueueItem>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct QueueItem {
    target: CrawlTarget,
}

// heap pops the highest score first
impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.target.score.cmp(&other.target.score)
    }
}

impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PriorityUrlQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    pub fn push(&mut self, mut target: CrawlTarget) {
        target.score = Self::calculate_score(&target);
        self.heap.push(QueueItem { target });
    }

    pub fn pop(&mut self) -> Option<CrawlTarget> {
        self.heap.pop().map(|item| item.target)
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    fn calculate_score(target: &CrawlTarget) -> u32 {
        let mut score: i32 = 100;
        if target.depth > 4 {
            score -= (target.depth as i32 - 4) * 4;
        }

        let path = target.url.path().to_lowercase();
        let high_value_keywords = ["id", "key", "token", "uid"];
        for keyword in high_value_keywords.iter() {
            if path.contains(keyword) || target.url.query().map_or(false, |q| q.contains(keyword)) {
                score += 12;
                break;
            }
        }

        let medium_value_keywords = ["admin", "dashboard", "login"];
        for keyword in medium_value_keywords.iter() {
            if path.contains(keyword) {
                score += 8;
                break;
            }
        }

        let api_keywords = ["/api/", "/v1/", "/graphql"];
        for keyword in api_keywords.iter() {
            if path.contains(keyword) {
                score += 7;
                break;
            }
        }

        if target.url.query().is_some() {
            score += 10;
        }

        if target.is_form_action {
            score += 5;
        }

        if let Some(segments) = target.url.path_segments() {
            if let Some(last) = segments.last() {
                if let Some(ext_idx) = last.rfind('.') {
                    let ext = &last[ext_idx + 1..];
                    match ext {
                        "css" | "js" | "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "woff"
                        | "woff2" | "ttf" => {
                            score -= 6;
                        }
                        "php" | "asp" | "aspx" | "jsp" | "jspx" => {
                            score += 6;
                        }
                        _ => {}
                    }
                }
            }
        }
        if score < 0 { 0 } else { score as u32 }
    }
}
