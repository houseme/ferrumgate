use super::*;
use fg_admin::{ApiJson, RouteModels};
use schemars::JsonSchema;

#[tokio::test]
async fn modeled_json_operation_uses_serde_request_and_response_shapes() -> Result<()> {
    #[derive(Deserialize, Serialize, JsonSchema)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct Input {
        display_name: String,
    }
    #[derive(Serialize, JsonSchema)]
    struct Output {
        accepted: String,
        #[serde(skip_serializing)]
        #[allow(dead_code)]
        internal: bool,
    }
    let admin = ApiRouter::new(principal)
        .modeled_route(
            Method::POST,
            "/api/ddns/rules/{key}",
            "Accept a fixture rule",
            RouteModels::default()
                .request::<Input>()
                .response::<Output>(),
            |ApiJson(input): ApiJson<Input>| async move {
                Json(Output {
                    accepted: input.display_name,
                    internal: true,
                })
            },
        )
        .finish();
    let operation = &admin.document()["paths"]["/api/ddns/rules/{key}"]["post"];
    assert_eq!(operation["parameters"][0]["name"], "key");
    let request = &operation["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(request["required"], json!(["displayName"]));
    assert_eq!(request["additionalProperties"], false);
    let response = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(response["required"], json!(["accepted"]));
    assert!(response["properties"]["internal"].is_null());
    let server = Server::start(admin.router).await?;
    let (status, _, response) = server
        .call(
            "POST",
            "/api/ddns/rules/1",
            &EDIT,
            r#"{"displayName":"fixture"}"#,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response, json!({"accepted":"fixture"}));
    Ok(())
}
