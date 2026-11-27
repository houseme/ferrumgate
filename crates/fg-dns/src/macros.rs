//! 提供商的 trait 实现与注册表条目宏。
//!
//! 提供商类型写固有的 `async fn upsert / add_txt / delete_txt /
//! find_records / remove_record`，宏负责把它们包装成盒装 Future 的 trait
//! 方法（本 crate 不引入 async-trait 依赖）。
//!
//! feature 关闭时部分宏不会被使用（测试与 --all-features 构建统一覆盖），
//! 这里整体关闭 unused 警告。

#![allow(unused_macros, unused_imports)]

/// 为提供商类型实现 [`crate::DnsProvider`]。
macro_rules! impl_provider {
    ($ty:ty, $meta:expr) => {
        impl $crate::DnsProvider for $ty {
            fn meta(&self) -> &'static $crate::Meta {
                &$meta
            }
            fn upsert<'a>(
                &'a self,
                rec: &'a $crate::Record,
            ) -> $crate::BoxFut<'a, Result<$crate::UpsertAction, $crate::ProviderError>> {
                Box::pin(async move { <$ty>::upsert(self, rec).await })
            }
        }
    };
}

/// 为提供商类型实现 [`crate::TxtRecords`]。
macro_rules! impl_txt {
    ($ty:ty) => {
        impl $crate::TxtRecords for $ty {
            fn add_txt<'a>(
                &'a self,
                zone: &'a str,
                sub: &'a str,
                value: &'a str,
            ) -> $crate::BoxFut<'a, Result<(), $crate::ProviderError>> {
                Box::pin(async move { <$ty>::add_txt(self, zone, sub, value).await })
            }
            fn delete_txt<'a>(
                &'a self,
                zone: &'a str,
                sub: &'a str,
                value: &'a str,
            ) -> $crate::BoxFut<'a, Result<(), $crate::ProviderError>> {
                Box::pin(async move { <$ty>::delete_txt(self, zone, sub, value).await })
            }
        }
    };
}

/// 为提供商类型实现 [`crate::Deleter`]。
macro_rules! impl_deleter {
    ($ty:ty) => {
        impl $crate::Deleter for $ty {
            fn find_records<'a>(
                &'a self,
                rec: &'a $crate::Record,
            ) -> $crate::BoxFut<'a, Result<Vec<$crate::delete::RemoteRecord>, $crate::ProviderError>>
            {
                Box::pin(async move { <$ty>::find_records(self, rec).await })
            }
            fn remove_record<'a>(
                &'a self,
                rec: &'a $crate::Record,
                remote: &'a $crate::delete::RemoteRecord,
            ) -> $crate::BoxFut<'a, Result<(), $crate::ProviderError>> {
                Box::pin(async move { <$ty>::remove_record(self, rec, remote).await })
            }
        }
    };
}

/// 注册表条目。`txt` 变体要求构造类型实现 [`crate::TxtRecords`]，
/// 与 `Meta.supports_acme = true` 的能力标记在编译期保持一致。
macro_rules! register_provider {
    (txt, $meta:expr, $ctor:expr) => {
        (&$meta, {
            fn factory(
                creds: $crate::Credentials,
                http: std::sync::Arc<$crate::http::OutboundHttp>,
            ) -> Result<Box<dyn $crate::DnsProvider>, $crate::ProviderError> {
                Ok($crate::box_txt($ctor(creds, http)?))
            }
            factory as $crate::Factory
        })
    };
    ($meta:expr, $ctor:expr) => {
        (&$meta, {
            fn factory(
                creds: $crate::Credentials,
                http: std::sync::Arc<$crate::http::OutboundHttp>,
            ) -> Result<Box<dyn $crate::DnsProvider>, $crate::ProviderError> {
                Ok($crate::box_provider($ctor(creds, http)?))
            }
            factory as $crate::Factory
        })
    };
}

// 使 `crate::impl_provider!(…)` 等路径调用可用。
// feature 关闭时部分宏暂未被使用。
#[allow(unused_imports)]
pub(crate) use {impl_deleter, impl_provider, impl_txt, register_provider};
