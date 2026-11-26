use schemars::{JsonSchema, generate::SchemaSettings};
use serde_json::{Value, json};

use crate::StreamPolicy;

#[derive(Clone, Default)]
pub struct RouteModels {
    pub(crate) parameters: Vec<Value>,
    pub(crate) request: Option<Value>,
    pub(crate) response: Option<Value>,
    pub(crate) stream: Option<StreamPolicy>,
}

impl RouteModels {
    /// Documents the form-encoded fields of a query extractor.
    pub fn query<T: JsonSchema>(mut self) -> Self {
        let schema = schema::<T>(false);
        let properties = schema["properties"]
            .as_object()
            .expect("an API query model must have named fields");
        let required = schema["required"].as_array();
        self.parameters = properties
            .iter()
            .map(|(name, field)| {
                let required = required.is_some_and(|keys| keys.iter().any(|key| key == name));
                json!({"name":name, "in":"query", "required":required, "schema":field})
            })
            .collect();
        self
    }

    pub fn request<T: JsonSchema>(mut self) -> Self {
        self.request = Some(json!({"required":true, "content":{
            "application/json":{"schema":schema::<T>(false)}
        }}));
        self
    }

    pub(crate) fn ignored_request_fields(mut self, names: &[&str]) -> Self {
        if !names.is_empty()
            && let Some(request) = &mut self.request
        {
            let model = &mut request["content"]["application/json"]["schema"];
            if model["properties"].is_null() {
                model["properties"] = json!({});
            }
            let properties = model["properties"]
                .as_object_mut()
                .expect("named item properties");
            for &name in names {
                properties.entry(name).or_insert_with(|| json!({}));
            }
        }
        self
    }

    pub fn response<T: JsonSchema>(mut self) -> Self {
        self.response = Some(json!({"application/json":{"schema":schema::<T>(true)}}));
        self
    }

    pub fn stream(mut self, policy: StreamPolicy, media: &[&str]) -> Self {
        self.stream = Some(policy);
        self.response = Some(Value::Object(
            media
                .iter()
                .map(|mime| {
                    (
                        (*mime).to_owned(),
                        json!({"schema":{"type":"string","format":"binary"}}),
                    )
                })
                .collect(),
        ));
        self
    }
}

#[derive(serde::Serialize, JsonSchema)]
pub(crate) struct OkResponse {
    pub ok: bool,
}

fn schema<T: JsonSchema>(response: bool) -> Value {
    let settings = SchemaSettings::openapi3().with(|settings| {
        settings.meta_schema = None;
        settings.inline_subschemas = true;
    });
    let settings = if response {
        settings.for_serialize()
    } else {
        settings
    };
    settings
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}
