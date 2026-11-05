//! Exercise discovery through the production router with a prefixed authority.
use salvo::test::{ResponseExt, TestClient};

#[test]
fn describe_keeps_authority_paths_and_advertises_a_valid_origin() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut config = coland_test_support::app_config();
                    config.account_authority_url = Some("https://station.example/auth/".to_owned());
                    let app = coland_http::service(coland_test_support::app_state(config));
                    let mut response =
                        TestClient::get("http://server/_arkret/describe?service_kind=station")
                            .add_header("Arkret-Operation", "ak.server.read.describe.v1", true)
                            .send(&app)
                            .await;
                    assert_eq!(response.status_code, Some(salvo::http::StatusCode::OK));
                    let description: serde_json::Value = response.take_json().await.unwrap();
                    let auth = &description["authentication_metadata"];
                    assert_eq!(
                        auth["account_authority"]["origin"],
                        "https://station.example"
                    );
                    assert_eq!(
                        auth["account_authority"]["gate_account_base_url"],
                        "https://station.example/auth/_arkret/gate/account"
                    );
                    assert_eq!(
                        auth["methods"][0]["issuer_uri"],
                        "https://station.example/auth/"
                    );
                });
        })
        .unwrap()
        .join()
        .unwrap();
}
