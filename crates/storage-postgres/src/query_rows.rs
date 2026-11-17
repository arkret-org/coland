use diesel::QueryableByName;
use diesel::sql_types::{Bool, Jsonb};
use serde_json::Value;

#[derive(QueryableByName)]
pub struct JsonPayloadRow {
    #[diesel(sql_type = Jsonb)]
    pub payload: Value,
}

#[derive(QueryableByName)]
pub struct ExistsRow {
    #[diesel(sql_type = Bool)]
    pub present: bool,
}
