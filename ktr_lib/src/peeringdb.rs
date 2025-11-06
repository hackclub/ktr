//! PeeringDB says (https://docs.peeringdb.com/howto/peeringdb-py/):
//!
//! > The SQL data structure might change without notice. Please do not build tools that make
//! > SQL queries. We suggest using our library to make API calls on your local cache. We
//! > maintain the library and commit to maintaining the API functionality, even if the
//! > underlying database structure changes.
//!
//! So, I built a tool that makes SQL queries.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;

use crate::metadata::{Asn, GeographicScope, Network, NetworkProtocols, NetworkType, Organization};

#[derive(Error, Debug)]
pub enum PeeringDbError {
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
}

pub struct PeeringDbManager {
    conn: Connection,
}

impl PeeringDbManager {
    pub fn connect(db_path: impl AsRef<Path>) -> Result<Self, PeeringDbError> {
        Ok(PeeringDbManager {
            conn: Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?,
        })
    }

    pub fn network_by_asn(&self, asn: Asn) -> Result<Option<Network>, PeeringDbError> {
        self.conn
            .query_row(
                "SELECT * FROM peeringdb_network WHERE asn=?1",
                [asn.0],
                |row| self.row_to_network(row),
            )
            .optional()
            .map_err(PeeringDbError::SqliteError)
    }

    fn row_to_network(&self, row: &Row) -> Result<Network, rusqlite::Error> {
        let organization = self.conn.query_row(
            "SELECT * FROM peeringdb_organization WHERE id=?1",
            [row.get::<_, usize>("org_id")?],
            |row| self.row_to_organization(row),
        )?;
        Ok(Network {
            id: row.get("id")?,
            name: row.get("name")?,
            organization,
            url: row.get("website")?,
            geographic_scope: GeographicScope::from_peeringdb_str(
                row.get::<_, String>("info_scope")?.as_str(),
            ),
            asn: Asn(row.get("asn")?),
            network_type: NetworkType::from_peeringdb_str(
                row.get::<_, String>("info_type")?.as_str(),
            ),
            protocols: Some(NetworkProtocols {
                unicast_ipv4: row.get("info_unicast")?,
                multicast: row.get("info_multicast")?,
                ipv6: row.get("info_ipv6")?,
                never_via_route_servers: row.get("info_never_via_route_servers")?,
            }),
        })
    }

    fn row_to_organization(&self, row: &Row) -> Result<Organization, rusqlite::Error> {
        Ok(Organization {
            id: row.get("id")?,
            name: row.get("name")?,
            url: row.get("website")?,
        })
    }
}
