use std::{collections::BTreeSet, io::Write, path::Path, sync::Arc};

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    handler::Handler,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodFilter, on},
};
use fg_core::registry::{Enabled, Registry, Status};
use serde_json::{Value, json};

use crate::{
    ApiError,
    http::boundary,
    scope::{Access, module_of, required},
};

pub enum Principal {
    Session { read_only: bool },
    Token { scopes: Vec<String> },
}

type Auth = Arc<dyn Fn(&HeaderMap) -> Option<Principal> + Send + Sync>;

struct Operation {
    method: Method,
    path: &'static str,
    summary: &'static str,
    access: Access<'static>,
}

#[derive(Clone)]
struct Policy {
    auth: Auth,
    access: Access<'static>,
}

pub struct ApiRouter {
    router: Router,
    operations: Vec<Operation>,
    auth: Auth,
    modules: Option<Arc<(Registry, Enabled)>>,
}

impl Default for ApiRouter {
    fn default() -> Self {
        Self::new(|_| None)
    }
}

impl ApiRouter {
    pub fn new(
        authenticate: impl Fn(&HeaderMap) -> Option<Principal> + Send + Sync + 'static,
    ) -> Self {
        Self {
            router: Router::new(),
            operations: Vec::new(),
            auth: Arc::new(authenticate),
            modules: None,
        }
    }

    pub fn with_modules(mut self, registry: Registry, enabled: Enabled) -> Self {
        assert!(
            self.operations.is_empty(),
            "configure modules before declaring routes"
        );
        self.modules = Some(Arc::new((registry, enabled)));
        self
    }

    pub fn route<H, T>(
        mut self,
        method: Method,
        path: &'static str,
        summary: &'static str,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        assert!(
            module_of(path).is_some(),
            "admin route requires an /api/ path"
        );
        assert_ne!(
            path, "/api/openapi.json",
            "OpenAPI is installed by the builder"
        );
        if matches!(self.status(path), Some(Status::Disabled | Status::Absent)) {
            return self;
        }
        let operation = Operation {
            access: required(&method, path),
            method,
            path,
            summary,
        };
        assert_ne!(
            operation.access,
            Access::Public,
            "public API routes must provide their own authentication"
        );
        self.mount(operation, handler);
        self
    }

    fn mount<H, T>(&mut self, operation: Operation, handler: H)
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        let method =
            MethodFilter::try_from(operation.method.clone()).expect("supported API method");
        let policy = Policy {
            auth: self.auth.clone(),
            access: operation.access,
        };
        self.router = std::mem::take(&mut self.router).route(
            operation.path,
            on::<_, _, ()>(method, handler)
                .route_layer(middleware::from_fn_with_state(policy, authorize)),
        );
        self.operations.push(operation);
    }

    fn status(&self, path: &str) -> Option<Status> {
        let (registry, enabled) = self.modules.as_deref()?;
        registry.status(enabled, module_of(path)?)
    }

    pub fn finish(mut self) -> Admin {
        let openapi = Operation {
            method: Method::GET,
            path: "/api/openapi.json",
            summary: "Get the management API schema",
            access: required(&Method::GET, "/api/openapi.json"),
        };
        let document = document(self.operations.iter().chain(std::iter::once(&openapi)));
        let spec = Bytes::from(serde_json::to_vec(&document).expect("OpenAPI document serializes"));
        self.mount(openapi, move || async move {
            ([(header::CONTENT_TYPE, "application/json")], spec).into_response()
        });
        let modules = self.modules;
        let router = self
            .router
            .fallback(move |uri: Uri| async move {
                if let Some((registry, enabled)) = modules.as_deref()
                    && let Some(id) = module_of(uri.path())
                {
                    match registry.status(enabled, id) {
                        Some(Status::Disabled) => {
                            return ApiError::new(StatusCode::FORBIDDEN, "module is disabled");
                        }
                        Some(Status::Absent) => {
                            return ApiError::new(
                                StatusCode::NOT_FOUND,
                                "module is not included in this build",
                            );
                        }
                        _ => {}
                    }
                }
                ApiError::new(StatusCode::NOT_FOUND, "API route not found")
            })
            .method_not_allowed_fallback(|| async {
                ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
            })
            .layer(middleware::from_fn(boundary));
        Admin {
            router,
            operations: self.operations,
            document,
        }
    }
}

async fn authorize(State(policy): State<Policy>, request: Request, next: Next) -> Response {
    let Some(principal) = (policy.auth)(request.headers()) else {
        return ApiError::new(StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    let allowed = match principal {
        Principal::Session { read_only: false } => true,
        Principal::Session { read_only: true } => {
            policy.access.read_only() && matches!(*request.method(), Method::GET | Method::HEAD)
        }
        Principal::Token { scopes } => policy.access.allows_token(&scopes),
    };
    if !allowed {
        return ApiError::new(StatusCode::FORBIDDEN, "insufficient permission").into_response();
    }
    next.run(request).await
}

pub struct Admin {
    pub router: Router,
    operations: Vec<Operation>,
    document: Value,
}

impl Admin {
    pub fn document(&self) -> &Value {
        &self.document
    }

    pub fn export(&self, directory: &Path) -> Result<()> {
        std::fs::create_dir_all(directory)?;
        let mut json_file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer_pretty(&mut json_file, self.document())?;
        writeln!(json_file)?;
        let mut markdown = tempfile::NamedTempFile::new_in(directory)?;
        writeln!(
            markdown,
            "# FerrumGate Management API\n\n| Method | Path | Summary | Token scope |\n|---|---|---|---|"
        )?;
        for route in &self.operations {
            let access = route.access.to_string();
            let access = if access.is_empty() {
                "any valid token"
            } else {
                &access
            };
            writeln!(
                markdown,
                "| {} | `{}` | {} | {} |",
                route.method, route.path, route.summary, access
            )?;
        }
        json_file.persist(directory.join("openapi.json"))?;
        markdown.persist(directory.join("API.md"))?;
        Ok(())
    }
}

fn document<'a>(operations: impl Iterator<Item = &'a Operation>) -> Value {
    let mut paths = serde_json::Map::new();
    let mut tags = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for route in operations {
        let tag = if route.path == "/api/openapi.json" {
            "system"
        } else {
            module_of(route.path).expect("API route")
        };
        tags.insert(tag);
        match route.access {
            Access::Scope(scope) => {
                domains.insert(scope.domain);
            }
            Access::All(scopes) => domains.extend(scopes.iter().map(|scope| scope.domain)),
            Access::Any | Access::SessionOnly | Access::Public => {}
        }
        let parameters: Vec<_> = route
            .path
            .split('/')
            .filter_map(|piece| piece.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}}))
            .collect();
        let token = !matches!(route.access, Access::SessionOnly | Access::Public);
        let security = if token {
            json!([{"bearerAuth":[]}, {"sessionCookie":[]}])
        } else {
            json!([{"sessionCookie":[]}])
        };
        paths.entry(route.path).or_insert_with(|| json!({}))
            [route.method.as_str().to_ascii_lowercase()] = json!({
            "summary":route.summary, "tags":[tag], "parameters":parameters,
            "responses":{"200":{"description":"Success"},"401":{"description":"Authentication required"},"403":{"description":"Insufficient permission"}},
            "security":security,"x-required-scope":route.access.to_string(),"x-token-allowed":token
        });
    }
    json!({"openapi":"3.0.3", "info":{"title":"FerrumGate Management API","version":env!("CARGO_PKG_VERSION")},
        "tags":tags.into_iter().map(|name| json!({"name":name})).collect::<Vec<_>>(),"paths":paths,
        "components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"},"sessionCookie":{"type":"apiKey","in":"cookie","name":"gately_token"}}},
        "x-scope-domains":domains})
}
