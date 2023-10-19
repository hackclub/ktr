use std::{convert::Infallible, path::Path, str::FromStr};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;

use crate::whois_net::Asn;

#[derive(Error, Debug)]
pub enum PeeringDbError {
    #[error("sqlite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct Organization {
    pub id: usize,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum GeographicScope {
    /// Regional
    Regional,
    /// North America
    NorthAmerica,
    /// Asia Pacific
    AsiaPacific,
    /// Europe
    Europe,
    /// South America
    SouthAmerica,
    /// Africa
    Africa,
    /// Australia
    Australia,
    /// Middle East
    MiddleEast,
    /// Global
    Global,
    /// Other or not disclosed
    Other,
}

impl FromStr for GeographicScope {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Regional" => Self::Regional,
            "North America" => Self::NorthAmerica,
            "Asia Pacific" => Self::AsiaPacific,
            "Europe" => Self::Europe,
            "South America" => Self::SouthAmerica,
            "Africa" => Self::Africa,
            "Australia" => Self::Australia,
            "Middle East" => Self::MiddleEast,
            "Global" => Self::Global,
            _ => Self::Other,
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetworkType {
    /// NSP (network service provider)
    NSP,
    /// Content
    Content,
    /// Cable/DSL/ISP
    ISP,
    /// Enterprise
    Enterprise,
    /// Educational/Research
    Educational,
    /// Non-Profit
    NonProfit,
    /// Route Server
    RouteServer,
    /// Network Services
    NetworkServices,
    /// Route Collector
    RouteCollector,
    /// Government
    Government,
    /// Other or not disclosed
    Other,
}

impl FromStr for NetworkType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "NSP" => Self::NSP,
            "Content" => Self::Content,
            "Cable/DSL/ISP" => Self::ISP,
            "Enterprise" => Self::Enterprise,
            "Educational/Research" => Self::Educational,
            "Non-Profit" => Self::NonProfit,
            "Route Server" => Self::RouteServer,
            "Network Services" => Self::NetworkServices,
            "Route Collector" => Self::RouteCollector,
            "Government" => Self::Government,
            _ => Self::Other,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NetworkProtocols {
    pub unicast_ipv4: bool,
    pub multicast: bool,
    pub ipv6: bool,
    pub never_via_route_servers: bool,
}

#[derive(Debug, Clone)]
pub struct Network {
    pub id: usize,
    pub name: String,
    pub organization: Organization,
    pub url: String,
    pub geographic_scope: GeographicScope,
    pub asn: Asn,
    pub network_type: NetworkType,
    pub protocols: NetworkProtocols,
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
            geographic_scope: row.get::<_, String>("info_scope")?.parse().unwrap(), // PANICS: FromStr for GeographicScope should be infallible
            asn: Asn(row.get("asn")?),
            network_type: row.get::<_, String>("info_type")?.parse().unwrap(), // PANICS: FromStr for NetworkType should be infallible
            protocols: NetworkProtocols {
                unicast_ipv4: row.get("info_unicast")?,
                multicast: row.get("info_multicast")?,
                ipv6: row.get("info_ipv6")?,
                never_via_route_servers: row.get("info_never_via_route_servers")?,
            },
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
