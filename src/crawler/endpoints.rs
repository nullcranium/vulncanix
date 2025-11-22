// This module contains ALL paths and patterns for parameter discovery
use crate::crawler::types::{ParamLocation, ParamType, Parameter};

pub fn get_heuristic_parameters(path: &str) -> Vec<Parameter> {
    let mut parameters = Vec::new();

    // public endpoints
    const PUBLIC_ENDPOINTS: &[&str] = &[
        "/",
        "/home",
        "/index",
        "/health",
        "/status",
        "/ping",
        "/version",
        "/login",
        "/logout",
        "/register",
        "/signup",
        "/auth",
        "/session",
        "/forgot-password",
        "/reset-password",
        "/verify",
        "/activate",
        "/deactivate",
        "/contact",
        "/about",
        "/terms",
        "/privacy",
        "/help",
        "/support",
        "/faq",
    ];

    // user endpoints
    const USER_ENDPOINTS: &[&str] = &[
        "/user",
        "/users",
        "/user/profile",
        "/user/settings",
        "/user/account",
        "/user/security",
        "/user/password",
        "/user/permissions",
        "/user/notifications",
        "/users/list",
        "/users/search",
    ];

    // auth
    const AUTH_VARIANTS: &[&str] = &[
        "/auth/login",
        "/auth/logout",
        "/auth/register",
        "/auth/refresh",
        "/auth/token",
        "/auth/validate",
        "/oauth",
        "/oauth2",
        "/oauth/token",
        "/sso",
        "/sso/callback",
        "/jwt",
        "/jwt/refresh",
    ];

    // admin endpoints
    const ADMIN_ENDPOINTS: &[&str] = &[
        "/admin",
        "/admin/login",
        "/admin/logout",
        "/admin/dashboard",
        "/admin/users",
        "/admin/settings",
        "/admin/config",
        "/admin/system",
        "/admin/monitor",
        "/admin/logs",
        "/admin/audit",
        "/admin/backup",
        "/admin/restore",
        "/admin/api",
    ];

    // API generic
    const API_GENERIC: &[&str] = &[
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/internal",
        "/api/private",
        "/api/admin",
        "/api/public",
        "/api/auth",
        "/api/stats",
        "/api/health",
        "/api/config",
    ];

    // E-commerce
    const ECOMMERCE: &[&str] = &[
        "/product",
        "/products",
        "/products/list",
        "/products/search",
        "/products/filter",
        "/products/category",
        "/cart",
        "/checkout",
        "/orders",
        "/orders/history",
        "/payment",
        "/payment/verify",
        "/shipping",
        "/invoice",
        "/discount",
        "/coupon",
    ];

    // blog/CMS
    const BLOG_CMS: &[&str] = &[
        "/blog",
        "/blog/posts",
        "/blog/categories",
        "/blog/tags",
        "/blog/search",
        "/posts",
        "/post",
        "/post/new",
        "/post/edit",
        "/content",
        "/content/upload",
        "/media",
        "/media/upload",
    ];

    // file endpoints
    const FILE_ENDPOINTS: &[&str] = &[
        "/upload",
        "/upload/file",
        "/upload/image",
        "/files",
        "/files/list",
        "/files/download",
        "/files/view",
        "/attachments",
        "/attachments/upload",
        "/temp",
        "/tmp",
        "/backup",
        "/exports",
        "/imports",
    ];

    // search endpoints
    const SEARCH_ENDPOINTS: &[&str] = &[
        "/search",
        "/lookup",
        "/find",
        "/query",
        "/filter",
        "/explore",
        "/discover",
        "/suggest",
    ];

    // debug info
    const DEBUG_INFO: &[&str] = &[
        "/debug",
        "/debug/info",
        "/debug/logs",
        "/debug/vars",
        "/debug/routes",
        "/debug/config",
        "/debug/trace",
        "/phpinfo",
        "/server-status",
        "/server-info",
    ];

    // internal engineering
    const INTERNAL_ENGINEERING: &[&str] = &[
        "/internal",
        "/internal/metrics",
        "/internal/stats",
        "/internal/config",
        "/internal/health",
        "/internal/jobs",
        "/internal/queue",
        "/internal/prewarm",
        "/internal/sync",
    ];

    // dev endpoints
    const DEV_ENDPOINTS: &[&str] = &[
        "/dev",
        "/dev/api",
        "/dev/login",
        "/dev/test",
        "/sandbox",
        "/playground",
        "/mock",
        "/mock/api",
        "/experiments",
    ];

    // monitoring
    const MONITORING: &[&str] = &[
        "/metrics",
        "/stats",
        "/usage",
        "/telemetry",
        "/observability",
        "/performance",
        "/uptime",
        "/alerts",
    ];

    // payment/finance
    const PAYMENT_FINANCE: &[&str] = &[
        "/billing",
        "/billing/history",
        "/billing/methods",
        "/invoice",
        "/invoices",
        "/payment",
        "/payment/status",
        "/payment/verify",
        "/subscription",
        "/subscriptions",
    ];

    // admin hidden patterns
    const ADMIN_HIDDEN: &[&str] = &[
        "/administrator",
        "/controlpanel",
        "/cpanel",
        "/manage",
        "/management",
        "/root",
        "/superadmin",
        "/system",
        "/secure",
        "/restricted",
    ];

    // backup/hidden
    const BACKUP_HIDDEN: &[&str] = &[
        "/backup",
        "/db",
        "/dbdump",
        "/dump",
        "/export",
        "/sql",
        "/database",
        "/old",
        "/old-version",
        "/archive",
        "/config.old",
        "/config.bak",
    ];

    // risky
    const RISKY_ENDPOINTS: &[&str] = &[
        "/exec",
        "/run",
        "/cmd",
        "/command",
        "/shell",
        "/ssh",
        "/task",
        "/task/run",
        "/queue/worker",
        "/job/execute",
    ];

    // Laravel
    const LARAVEL: &[&str] = &[
        "/_debugbar",
        "/telescope",
        "/horizon",
        "/vendor/phpunit",
        "/storage/logs",
        "/storage/debug",
        "/api/documentation",
    ];

    // Django
    const DJANGO: &[&str] = &["/static", "/staticfiles", "/media"];

    // Rails
    const RAILS: &[&str] = &[
        "/rails/info",
        "/rails/console",
        "/assets",
        "/active_storage",
    ];

    // Node.js
    const NODEJS: &[&str] = &["/node_modules", "/express", "/next", "/api/graphql"];

    // sensitive files
    const GET_ENDPOINTS: &[&str] = &[
        "/.env",
        "/.git",
        "/.git/config",
        "/.git/HEAD",
        "/.svn",
        "/.hg",
        "/.DS_Store",
        "/config.json",
        "/config.yml",
        "/config.ini",
        "/credentials",
        "/secrets",
        "/secret",
        "/keys",
        "/key",
        "/private",
        "/private.key",
        "/id_rsa",
        "/id_rsa.pub",
    ];

    // password reset
    const PASSWD_RESET: &[&str] = &[
        "/reset",
        "/reset/token",
        "/reset/validate",
        "/password/reset",
        "/password/change",
        "/password/set",
        "/change-password",
        "/verify-code",
        "/otp",
        "/otp/verify",
        "/2fa",
        "/2fa/disable",
    ];

    // object storage
    const OBJECT_STORAGE: &[&str] = &[
        "/storage",
        "/storage/logs",
        "/storage/uploads",
        "/storage/app",
        "/public/uploads",
        "/public/files",
        "/uploads",
        "/backup/files",
        "/bucket",
        "/s3",
        "/s3/object",
        "/gcs",
        "/minio",
    ];

    // cloud metadata
    const CLOUD_METADATA: &[&str] = &[
        "/metadata",
        "/instance",
        "/instance/identity",
        "/latest/meta-data",
        "/computeMetadata",
    ];

    // SSRF
    const SSRF_MAGNETS: &[&str] = &[
        "/proxy",
        "/fetch",
        "/fetch/url",
        "/download",
        "/download?url=",
        "/reader",
        "/reader/load",
        "/callback",
        "/webhook",
        "/webhook/test",
        "/ping?url=",
        "/test?url=",
    ];

    // debug
    const DEBUG: &[&str] = &[
        "/logs",
        "/logs/view",
        "/logs/error",
        "/trace",
        "/stacktrace",
        "/stack",
        "/debug/dump",
        "/dump",
        "/info.php",
        "/test.php",
        "/debug/token",
    ];

    // job queue danger
    const JOB_QUEUE_DANGER: &[&str] = &[
        "/queue",
        "/queue/push",
        "/queue/pop",
        "/queue/test",
        "/job",
        "/job/run",
        "/job/execute",
        "/worker",
        "/cron",
        "/cron/run",
    ];

    // flags internal
    const FLAGS_INTERNAL: &[&str] = &[
        "/feature",
        "/flags",
        "/toggle",
        "/toggle/feature",
        "/beta",
        "/beta/enable",
        "/experiment",
        "/experiments/rollout",
    ];

    // DB access
    const DB_ACCESS: &[&str] = &[
        "/db",
        "/database",
        "/database/browser",
        "/adminer",
        "/phpmyadmin",
        "/pma",
        "/dbadmin",
        "/pgadmin",
        "/sql",
        "/sql/test",
        "/sql/query",
        "/dba",
    ];

    // admin backdoors
    const ADMIN_BACKDOORS: &[&str] = &[
        "/adminer.php",
        "/admin.php",
        "/control",
        "/panel",
        "/manage/login",
        "/system/login",
        "/hidden-admin",
        "/superuser",
        "/rootpanel",
    ];

    // API docs and schemas
    const API_DOCS: &[&str] = &[
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/openapi",
        "/v2/api-docs",
        "/v3/api-docs",
        "/docs/api",
        "/graphql",
        "/graphql/playground",
        "/graphiql",
    ];

    // automation exposed
    const AUTOMATION_EXPOSED: &[&str] = &[
        "/automation",
        "/automation/run",
        "/script",
        "/script/run",
        "/script/execute",
        "/task/execute",
        "/task/schedule",
        "/pipeline",
        "/pipeline/run",
    ];

    // check each category and add appropriate parameters

    for endpoint in PUBLIC_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "redirect".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "next".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "return_url".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in USER_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "user_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "username".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in AUTH_VARIANTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "token".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "client_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "redirect_uri".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "scope".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in ECOMMERCE {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "product_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "sku".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "quantity".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in BLOG_CMS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "post_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "category".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "tag".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in FILE_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "filename".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "file_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "path".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in SEARCH_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "q".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "query".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "filter".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "sort".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in SSRF_MAGNETS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "url".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "target".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "endpoint".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in DB_ACCESS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "table".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "query".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "database".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in JOB_QUEUE_DANGER {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "job_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "task".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "command".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in API_DOCS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "version".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "format".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in OBJECT_STORAGE {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "bucket".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "object".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "key".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in FLAGS_INTERNAL {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "feature".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "enabled".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in PAYMENT_FINANCE {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "plan_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "amount".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "currency".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in AUTOMATION_EXPOSED {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "script_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "pipeline_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in PASSWD_RESET {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "reset_token".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "otp".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "code".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in CLOUD_METADATA {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "instance_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "metadata_key".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in RISKY_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "cmd".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "args".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "shell".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in ADMIN_ENDPOINTS
        .iter()
        .chain(ADMIN_HIDDEN.iter())
        .chain(ADMIN_BACKDOORS.iter())
    {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "action".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "module".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in DEBUG_INFO.iter().chain(DEBUG.iter()) {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "debug".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "trace_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in INTERNAL_ENGINEERING {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "service".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "region".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in DEV_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "env".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "mode".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in MONITORING {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "metric_name".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "interval".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in GET_ENDPOINTS {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "file".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in BACKUP_HIDDEN {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "backup_id".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            parameters.push(Parameter {
                name: "file".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in LARAVEL
        .iter()
        .chain(DJANGO.iter())
        .chain(RAILS.iter())
        .chain(NODEJS.iter())
    {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "framework".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    for endpoint in API_GENERIC {
        if path.contains(endpoint) {
            parameters.push(Parameter {
                name: "api_key".to_string(),
                param_type: ParamType::Heuristic,
                location: ParamLocation::Path,
                value: None,
            });
            break;
        }
    }

    parameters
}
