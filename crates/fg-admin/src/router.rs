use std::{collections::BTreeSet, io::Write, path::Path, sync::Arc};

use anyhow::Result;
use axum::{
    Router,
    body::{Bytes, HttpBody},
    extract::{Request, State},
    handler::Handler,
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodFilter, on},
};
use fg_auth::{
    AccountManager, Identity, Role,
    passkey::{Passkeys, Url},
};
use fg_core::registry::{CATALOG, Enabled, Registry, Status};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::{
    AdminAssets, ApiError, Localizer, RouteModels, Translation,
    http::{Presentation, RenderPolicy, boundary},
    login::{self, COOKIE_NAME, SessionCookies, password_fix_allowed, session_token},
    response::MAX_TRANSFORMS,
    scope::{Access, bootstrap_route, module_of, required},
    upload,
};

pub enum Principal {
    Session { read_only: bool },
    Token { scopes: Vec<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamPolicy {
    WritersOnly,
    /// The handler must filter the stream using the `ReadOnly` request extension.
    ReadOnlySafe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnly(pub bool);

enum Authenticated {
    Account(Identity),
    External(Principal),
}

type Auth = Arc<dyn Fn(&HeaderMap) -> Option<Authenticated> + Send + Sync>;

struct Operation {
    method: Method,
    path: String,
    summary: &'static str,
    access: Arc<Access<'static>>,
    mode: RouteMode,
    models: RouteModels,
}

impl Operation {
    fn new(
        method: Method,
        path: String,
        summary: &'static str,
        mode: RouteMode,
        models: RouteModels,
    ) -> Self {
        assert!(
            module_of(&path).is_some(),
            "admin route requires an /api/ path"
        );
        Self {
            access: Arc::new(required(&method, &path).into_owned()),
            method,
            path,
            summary,
            mode,
            models,
        }
    }

    fn documented(&self) -> bool {
        !bootstrap_route(&self.method, &self.path)
    }
}

#[derive(Clone, Copy, Default)]
struct RouteMode {
    stream: Option<StreamPolicy>,
    translation: Translation,
    upload_limit: Option<u64>,
    static_document: bool,
}

#[derive(Clone)]
struct Policy {
    auth: Auth,
    access: Arc<Access<'static>>,
    mode: RouteMode,
}

pub struct ApiRouter {
    router: Router,
    operations: Vec<Operation>,
    auth: Auth,
    modules: Option<Arc<(Registry, Enabled)>>,
    presentation: Presentation,
    assets: Option<AdminAssets>,
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
            auth: Arc::new(move |headers| authenticate(headers).map(Authenticated::External)),
            modules: None,
            assets: None,
            presentation: Presentation {
                localizer: None,
                budget: Arc::new(Semaphore::new(MAX_TRANSFORMS)),
            },
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

    pub fn with_localizer(mut self, localizer: Localizer) -> Self {
        self.presentation.localizer = Some(localizer);
        self
    }

    pub fn with_assets(mut self, assets: AdminAssets) -> Self {
        self.assets = Some(assets);
        self
    }

    pub fn with_token_management(self, tokens: Arc<fg_auth::token::TokenManager>) -> Self {
        let domains = crate::token_routes::domains(self.modules.as_deref(), &tokens);
        tokens.set_domains(domains.iter().map(|domain| domain.id.to_owned()));
        crate::token_routes::mount(self, tokens, domains)
    }

    /// Installs account routes before other routes. Set `secure` for an externally HTTPS listener.
    /// The listener must supply `ConnectInfo<SocketAddr>`. Other authenticators supply API tokens.
    pub fn with_accounts(
        self,
        accounts: Arc<AccountManager>,
        external_prefix: &str,
        secure: bool,
    ) -> Result<Self> {
        self.mount_accounts(accounts, external_prefix, secure, None)
    }

    /// Installs account and Passkey routes for the configured public origin.
    pub fn with_passkey_accounts(
        self,
        accounts: Arc<AccountManager>,
        external_prefix: &str,
        origin: &Url,
    ) -> Result<Self> {
        let passkeys = Passkeys::new(accounts.clone(), origin)?;
        self.mount_accounts(
            accounts,
            external_prefix,
            origin.scheme() == "https",
            Some(passkeys),
        )
    }

    fn mount_accounts(
        mut self,
        accounts: Arc<AccountManager>,
        external_prefix: &str,
        secure: bool,
        passkeys: Option<Passkeys>,
    ) -> Result<Self> {
        assert!(
            self.operations.is_empty(),
            "configure accounts before declaring routes"
        );
        let cookies = SessionCookies::new(external_prefix, secure)?;
        let previous = self.auth;
        let verifier = accounts.clone();
        self.auth = Arc::new(move |headers| {
            if let Some(identity) =
                session_token(headers).and_then(|token| verifier.identify(token))
            {
                return Some(Authenticated::Account(identity));
            }
            previous(headers).filter(|principal| {
                matches!(principal, Authenticated::External(Principal::Token { .. }))
            })
        });
        let mut disabled = Vec::new();
        let mut absent = Vec::new();
        if let Some((registry, enabled)) = self.modules.as_deref() {
            for module in CATALOG {
                match registry.status(enabled, module.id) {
                    Some(Status::Disabled) => disabled.push(module.id),
                    Some(Status::Absent) => absent.push(module.id),
                    _ => {}
                }
            }
        }
        Ok(login::mount(
            self, accounts, cookies, disabled, absent, passkeys,
        ))
    }

    pub fn route<H, T>(
        self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        self.modeled_route(method, path, summary, RouteModels::default(), handler)
    }

    pub fn modeled_route<H, T>(
        self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        models: RouteModels,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        self.register(
            method,
            path.into(),
            summary,
            RouteMode {
                stream: models.stream,
                ..RouteMode::default()
            },
            models,
            handler,
        )
    }

    /// Installs a login entry point or a module's public endpoint.
    /// The handler owns any endpoint-specific credential checks.
    pub fn public_route<H, T>(
        mut self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        let operation = Operation::new(
            method,
            path.into(),
            summary,
            RouteMode::default(),
            RouteModels::default(),
        );
        assert_eq!(
            *operation.access,
            Access::Public,
            "route is not a public API endpoint"
        );
        let module = module_of(&operation.path).expect("API path");
        assert!(
            bootstrap_route(&operation.method, &operation.path)
                || CATALOG.iter().any(|entry| entry.id == module),
            "public module route requires a known module prefix"
        );
        self.mount(operation, handler);
        self
    }

    pub fn translated_route<H, T>(
        self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        translation: Translation,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        if let Translation::Fields(fields) = translation {
            assert!(
                fields.iter().all(|field| field.starts_with('/')),
                "translation fields must be non-root JSON pointers"
            );
        }
        self.register(
            method,
            path.into(),
            summary,
            RouteMode {
                translation,
                ..RouteMode::default()
            },
            RouteModels::default(),
            handler,
        )
    }

    pub fn stream_route<H, T>(
        self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        policy: StreamPolicy,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        self.register(
            method,
            path.into(),
            summary,
            RouteMode {
                stream: Some(policy),
                ..RouteMode::default()
            },
            RouteModels::default(),
            handler,
        )
    }

    /// Adds a streaming upload with a caller-defined maximum size and the shared read-rate policy.
    pub fn upload_route<H, T>(
        self,
        method: Method,
        path: impl Into<String>,
        summary: &'static str,
        limit: u64,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        assert!(
            matches!(method, Method::POST | Method::PUT) && limit > 0,
            "uploads require POST or PUT and a positive limit"
        );
        self.register(
            method,
            path.into(),
            summary,
            RouteMode {
                upload_limit: Some(limit),
                ..RouteMode::default()
            },
            RouteModels::default(),
            handler,
        )
    }

    fn register<H, T>(
        mut self,
        method: Method,
        path: String,
        summary: &'static str,
        mode: RouteMode,
        models: RouteModels,
        handler: H,
    ) -> Self
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        assert_ne!(
            path, "/api/openapi.json",
            "OpenAPI is installed by the builder"
        );
        let operation = Operation::new(method, path, summary, mode, models);
        assert_ne!(
            *operation.access,
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
        if matches!(
            self.status(&operation.path),
            Some(Status::Disabled | Status::Absent)
        ) {
            return;
        }
        let method =
            MethodFilter::try_from(operation.method.clone()).expect("supported API method");
        let route = on::<_, _, ()>(method, handler);
        let route = if *operation.access == Access::Public {
            route
        } else {
            let policy = Policy {
                auth: self.auth.clone(),
                access: operation.access.clone(),
                mode: operation.mode,
            };
            route.route_layer(middleware::from_fn_with_state(policy, authorize))
        };
        self.router = std::mem::take(&mut self.router).route(&operation.path, route);
        self.operations.push(operation);
    }

    fn status(&self, path: &str) -> Option<Status> {
        let (registry, enabled) = self.modules.as_deref()?;
        registry.status(enabled, module_of(path)?)
    }

    pub fn finish(mut self) -> Admin {
        let openapi = Operation::new(
            Method::GET,
            "/api/openapi.json".into(),
            "Get the management API schema",
            RouteMode {
                // Generated from route definitions and types, with no instance data.
                static_document: true,
                ..RouteMode::default()
            },
            RouteModels::default(),
        );
        let document = document(self.operations.iter().chain(std::iter::once(&openapi)));
        let spec = Bytes::from(serde_json::to_vec(&document).expect("OpenAPI document serializes"));
        self.mount(openapi, move || async move {
            ([(header::CONTENT_TYPE, "application/json")], spec).into_response()
        });
        let modules = self.modules;
        let assets = self.assets;
        let router = self
            .router
            .fallback(move |request: Request| async move {
                let path = request.uri().path();
                if path != "/api"
                    && !path.starts_with("/api/")
                    && let Some(assets) = assets.as_ref()
                {
                    return assets.serve(path, request.method(), request.headers());
                }
                if let Some((registry, enabled)) = modules.as_deref()
                    && let Some(id) = module_of(path)
                {
                    match registry.status(enabled, id) {
                        Some(Status::Disabled) => {
                            return ApiError::new(StatusCode::FORBIDDEN, "module is disabled")
                                .into_response();
                        }
                        Some(Status::Absent) => {
                            return ApiError::new(
                                StatusCode::NOT_FOUND,
                                "module is not included in this build",
                            )
                            .into_response();
                        }
                        _ => {}
                    }
                }
                ApiError::new(StatusCode::NOT_FOUND, "API route not found").into_response()
            })
            .method_not_allowed_fallback(|| async {
                ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
            })
            .layer(middleware::from_fn_with_state(self.presentation, boundary));
        Admin {
            router,
            operations: self.operations,
            document,
        }
    }
}

async fn authorize(State(policy): State<Policy>, mut request: Request, next: Next) -> Response {
    let version = request.version();
    let reject_upload = policy.mode.upload_limit.is_some() && !request.body().is_end_stream();
    let reject = |error: ApiError| {
        let mut response = error.into_response();
        if reject_upload {
            upload::close_incomplete(&mut response, version);
        }
        response
    };
    let Some(principal) = (policy.auth)(request.headers()) else {
        return reject(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "authentication required",
        ));
    };
    let readonly_allowed =
        policy.access.read_only() && matches!(*request.method(), Method::GET | Method::HEAD);
    let (allowed, restricted) = match principal {
        Authenticated::Account(identity) => {
            if identity.must_change_password
                && !password_fix_allowed(request.method(), request.uri().path())
            {
                return reject(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "administrator password must be changed",
                ));
            }
            let restricted = identity.role == Role::Readonly;
            let allowed = !restricted || readonly_allowed;
            request.extensions_mut().insert(identity);
            (allowed, restricted)
        }
        Authenticated::External(Principal::Session { read_only: false }) => (true, false),
        Authenticated::External(Principal::Session { read_only: true }) => (readonly_allowed, true),
        Authenticated::External(Principal::Token { scopes }) => (
            policy.access.allows_token(&scopes),
            !policy.access.allows_unredacted(&scopes),
        ),
    };
    if !allowed || (restricted && policy.mode.stream == Some(StreamPolicy::WritersOnly)) {
        return reject(ApiError::new(
            StatusCode::FORBIDDEN,
            "insufficient permission",
        ));
    }
    let upload = match policy
        .mode
        .upload_limit
        .map(|limit| upload::protect(&mut request, limit))
        .transpose()
    {
        Ok(upload) => upload,
        Err(error) => return reject(error),
    };
    request.extensions_mut().insert(ReadOnly(restricted));
    let mut response = next.run(request).await;
    if let Some(upload) = upload {
        if let Some(error) = upload.error() {
            response = error.into_response();
        }
        if !upload.complete() {
            upload::close_incomplete(&mut response, version);
        }
    }
    response.extensions_mut().insert(RenderPolicy {
        restricted: restricted && !policy.mode.static_document,
        stream: policy.mode.stream.is_some(),
        translation: policy.mode.translation,
    });
    response
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
        for route in self.operations.iter().filter(|route| route.documented()) {
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
    for route in operations.filter(|route| route.documented()) {
        let tag = if route.path == "/api/openapi.json" {
            "system"
        } else {
            module_of(&route.path).expect("API route")
        };
        tags.insert(tag);
        match route.access.as_ref() {
            Access::Scope(scope) => {
                domains.insert(scope.domain.as_ref());
            }
            Access::All(scopes) => domains.extend(scopes.iter().map(|scope| scope.domain.as_ref())),
            Access::Any | Access::SessionOnly | Access::Public => {}
        }
        let mut parameters: Vec<_> = route
            .path
            .split('/')
            .filter_map(|piece| piece.strip_prefix('{')?.strip_suffix('}'))
            .map(|name| json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}}))
            .collect();
        parameters.extend(route.models.parameters.iter().cloned());
        let (security, token, unauthorized) = match *route.access {
            Access::Public => (json!([]), false, "Invalid module credential"),
            Access::SessionOnly => (
                json!([{"sessionCookie":[]}]),
                false,
                "Authentication required",
            ),
            _ => (
                json!([{"bearerAuth":[]}, {"sessionCookie":[]}]),
                true,
                "Authentication required",
            ),
        };
        let mut definition = json!({
            "summary":route.summary, "tags":[tag], "parameters":parameters,
            "responses":{"200":{"description":"Success"},"401":{"description":unauthorized},"403":{"description":"Insufficient permission"}},
            "security":security,"x-required-scope":route.access.to_string(),"x-token-allowed":token,"x-stream":route.mode.stream.is_some()
        });
        if let Some(limit) = route.mode.upload_limit {
            definition["x-upload-max-bytes"] = json!(limit);
        }
        if let Some(request) = &route.models.request {
            definition["requestBody"] = request.clone();
        }
        if let Some(response) = &route.models.response {
            definition["responses"]["200"]["content"] = response.clone();
        }
        paths.entry(route.path.clone()).or_insert_with(|| json!({}))
            [route.method.as_str().to_ascii_lowercase()] = definition;
    }
    json!({"openapi":"3.0.3", "info":{"title":"FerrumGate Management API","version":env!("CARGO_PKG_VERSION")},
        "tags":tags.into_iter().map(|name| json!({"name":name})).collect::<Vec<_>>(),"paths":paths,
        "components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"},"sessionCookie":{"type":"apiKey","in":"cookie","name":COOKIE_NAME}}},
        "x-scope-domains":domains})
}
