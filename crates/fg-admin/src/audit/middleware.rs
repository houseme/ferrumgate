//! The audit middleware, mounted inside authentication so each record can
//! name the actor, and around the handler so the status code is final.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::Extensions,
    middleware::Next,
    response::Response,
};
use fg_auth::{Identity, token::TokenIdentity};

use super::{AuditLog, Entry, rules, timestamp};
use crate::scope::module_of;

pub(crate) async fn observe(
    State(audit): State<Arc<AuditLog>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let category = rules::classify(&method, &path);
    let extensions = request.extensions();
    let actor = category.and_then(|_| actor_of(extensions));
    let ip = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.ip());
    let response = next.run(request).await;
    if let (Some(category), Some(actor), Some(ip)) = (category, actor, ip) {
        audit.record(Entry {
            time: timestamp(),
            actor,
            ip,
            via: None, // trusted proxy attribution arrives with WP-14
            category,
            module: module_of(&path).unwrap_or_default().to_owned(),
            method: method.as_str().to_owned(),
            path,
            status: response.status().as_u16(),
            detail: String::new(),
        });
    }
    response
}

fn actor_of(extensions: &Extensions) -> Option<String> {
    if let Some(identity) = extensions.get::<Identity>() {
        return Some(identity.username.clone());
    }
    extensions
        .get::<TokenIdentity>()
        .map(|token| format!("api-token:{}", token.name()))
}
