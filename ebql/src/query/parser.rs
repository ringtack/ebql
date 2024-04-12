use anyhow::{anyhow, Context, Result};
use nom_sql::{SelectStatement, SqlQuery};

pub fn parse_query(q: String) -> Result<SelectStatement> {
    match nom_sql::parse_query(&q) {
        Ok(q) => {
            match q {
                SqlQuery::Select(s) => Ok(s),
                _ => Err(anyhow!("Query {q} not supported")),
            }
        }
        Err(e) => Err(anyhow!("Failed to parse query {q}: {e}")),
    }
}
