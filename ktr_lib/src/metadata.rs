use std::fmt::Debug;

#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Asn(pub u32);

impl Debug for Asn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Organization {
    pub id: usize,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
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

impl GeographicScope {
    pub fn from_peeringdb_str(s: &str) -> Self {
        match s {
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
        }
    }

    pub fn from_country_code(c: &str) -> Self {
        match c {
            // North America
            "CA" | "US" | "MX" | "BZ" | "CR" | "SV" | "GT" | "HN" | "NI" | "PA" | "AI" | "AG"
            | "AW" | "BS" | "BB" | "BM" | "VG" | "KY" | "CU" | "CW" | "DM" | "DO" | "GD" | "GP"
            | "HT" | "JM" | "MQ" | "MS" | "PR" | "BL" | "KN" | "LC" | "MF" | "PM" | "VC" | "SX"
            | "TT" | "TC" | "VI" | "GL" => Self::NorthAmerica,

            // South America
            "AR" | "BO" | "BR" | "CL" | "CO" | "EC" | "FK" | "GF" | "GY" | "PY" | "PE" | "SR"
            | "UY" | "VE" => Self::SouthAmerica,

            // Europe
            "AL" | "AD" | "AM" | "AT" | "AZ" | "BY" | "BE" | "BA" | "BG" | "HR" | "CY" | "CZ"
            | "DK" | "EE" | "FI" | "FR" | "GE" | "DE" | "GR" | "HU" | "IS" | "IE" | "IT" | "XK"
            | "LV" | "LI" | "LT" | "LU" | "MK" | "MT" | "MD" | "MC" | "ME" | "NL" | "NO" | "PL"
            | "PT" | "RO" | "RU" | "SM" | "RS" | "SK" | "SI" | "ES" | "SE" | "CH" | "TR" | "UA"
            | "GB" | "VA" | "AX" | "GG" | "JE" | "IM" | "FO" | "GI" | "SJ" => Self::Europe,

            // Middle East
            "BH" | "EG" | "IR" | "IQ" | "IL" | "JO" | "KW" | "LB" | "OM" | "PS" | "QA" | "SA"
            | "SY" | "AE" | "YE" => Self::MiddleEast,

            // Africa
            "DZ" | "AO" | "BJ" | "BW" | "BF" | "BI" | "CM" | "CV" | "CF" | "TD" | "KM" | "CG"
            | "CD" | "CI" | "DJ" | "GQ" | "ER" | "SZ" | "ET" | "GA" | "GM" | "GH" | "GN" | "GW"
            | "KE" | "LS" | "LR" | "LY" | "MG" | "MW" | "ML" | "MR" | "MU" | "YT" | "MA" | "MZ"
            | "NA" | "NE" | "NG" | "RE" | "RW" | "ST" | "SN" | "SC" | "SL" | "SO" | "ZA" | "SS"
            | "SD" | "TZ" | "TG" | "TN" | "UG" | "EH" | "ZM" | "ZW" | "SH" => Self::Africa,

            // Australia/Oceania
            "AU" | "NZ" | "FJ" | "NC" | "PG" | "SB" | "VU" | "GU" | "KI" | "MH" | "FM" | "NR"
            | "MP" | "PW" | "WS" | "AS" | "CK" | "PF" | "NU" | "PN" | "TK" | "TO" | "TV" | "WF"
            | "NF" | "CX" | "CC" | "HM" | "TF" | "GS" => Self::Australia,

            // Asia/Pacific
            "AF" | "BD" | "BT" | "BN" | "KH" | "CN" | "HK" | "IN" | "ID" | "JP" | "KZ" | "KP"
            | "KR" | "KG" | "LA" | "MO" | "MY" | "MV" | "MN" | "MM" | "NP" | "PK" | "PH" | "SG"
            | "LK" | "TW" | "TJ" | "TH" | "TL" | "TM" | "UZ" | "VN" | "IO" => Self::AsiaPacific,

            // Antarctica
            "AQ" | "BV" => Self::Australia, // Grouped with Australia/Oceania

            // Unrecognized code
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub enum NetworkType {
    /// NSP (network service provider)
    Nsp,
    /// Content
    Content,
    /// Cable/DSL/ISP
    Isp,
    /// NSP or ISP
    NspOrIsp,
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

impl NetworkType {
    pub fn from_peeringdb_str(s: &str) -> Self {
        match s {
            "NSP" => Self::Nsp,
            "Content" => Self::Content,
            "Cable/DSL/ISP" => Self::Isp,
            "Enterprise" => Self::Enterprise,
            "Educational/Research" => Self::Educational,
            "Non-Profit" => Self::NonProfit,
            "Route Server" => Self::RouteServer,
            "Network Services" => Self::NetworkServices,
            "Route Collector" => Self::RouteCollector,
            "Government" => Self::Government,
            _ => Self::Other,
        }
    }

    pub fn from_bgptools_str(s: &str) -> Self {
        match s {
            "Unknown" => Self::Other,
            "Eyeball" => Self::NspOrIsp,
            "Content" => Self::Content,
            "Carrier" => Self::Isp,
            "T1" => Self::NspOrIsp,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct NetworkProtocols {
    pub unicast_ipv4: bool,
    pub multicast: bool,
    pub ipv6: bool,
    pub never_via_route_servers: bool,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Network {
    pub id: usize,
    pub name: String,
    pub organization: Organization,
    pub url: String,
    pub geographic_scope: GeographicScope,
    pub asn: Asn,
    pub network_type: NetworkType,
    pub protocols: Option<NetworkProtocols>,
}
