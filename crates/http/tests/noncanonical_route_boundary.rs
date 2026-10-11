use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
const INVENTORY: &str = include_str!("../../../noncanonical-route-inventory.jsonl");

#[derive(Debug, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
enum InventoryRecord {
    Metadata {
        schema: String,
        audit_status: String,
        finding: String,
        source: String,
        initial_private_path_count: usize,
        current_private_path_count: usize,
    },
    Route {
        methods: BTreeSet<String>,
        path: String,
        classification: String,
        side_effect: String,
        auth_boundary: String,
        caller_refs: Vec<String>,
        canonical_operation: Option<String>,
        decision_ref: String,
        owner: String,
    },
}

#[test]
fn inventory_tracks_every_noncanonical_product_route_once() {
    let actual = coland_http::openapi::product_registered_routes()
        .expect("production route tree must be inspectable")
        .into_iter()
        .filter(|(path, _)| path.starts_with("/_coland/"))
        .map(|(path, methods)| {
            (
                path,
                methods
                    .into_iter()
                    .map(|method| method.to_ascii_uppercase())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let records = INVENTORY
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<InventoryRecord>(line).expect("inventory line is JSON"))
        .collect::<Vec<_>>();

    let metadata = records
        .iter()
        .find_map(|record| match record {
            InventoryRecord::Metadata {
                schema,
                audit_status,
                finding,
                source,
                initial_private_path_count,
                current_private_path_count,
            } => Some((
                schema.clone(),
                audit_status.clone(),
                finding.clone(),
                source.clone(),
                *initial_private_path_count,
                *current_private_path_count,
            )),
            InventoryRecord::Route { .. } => None,
        })
        .expect("inventory metadata is required");
    assert_eq!(metadata.0, "coland.noncanonical_route_inventory.v1");
    assert_eq!(metadata.1, "closed");
    assert_eq!(metadata.2, "arkret-work/review_code.md");
    assert_eq!(metadata.3, "coland-http live Salvo router/OpenAPI");
    assert_eq!(metadata.4, 127);
    let mut inventoried = BTreeMap::new();
    for record in records {
        let InventoryRecord::Route {
            methods,
            path,
            classification,
            side_effect,
            auth_boundary,
            caller_refs,
            canonical_operation,
            decision_ref,
            owner,
        } = record
        else {
            continue;
        };
        assert!(
            matches!(
                classification.as_str(),
                "product_surface" | "operator_extraction" | "development_only"
            ),
            "{path} has an invalid classification"
        );
        assert!(!side_effect.trim().is_empty(), "{path} lacks side_effect");
        assert!(!methods.is_empty(), "{path} lacks HTTP methods");
        assert!(
            !auth_boundary.trim().is_empty(),
            "{path} lacks auth_boundary"
        );
        assert!(!decision_ref.trim().is_empty(), "{path} lacks decision_ref");
        assert!(!owner.trim().is_empty(), "{path} lacks owner");
        assert!(
            !caller_refs.is_empty()
                || canonical_operation.is_some()
                || decision_ref.starts_with("arkret-work/"),
            "{path} has neither a live caller, a canonical replacement, nor an explicit arkret-work decision"
        );
        assert!(
            inventoried.insert(path.clone(), methods).is_none(),
            "{path} is classified more than once"
        );
    }

    assert_eq!(
        actual, inventoried,
        "the committed inventory must exactly match every current /_coland route and method"
    );
    assert_eq!(metadata.5, actual.len());
}
