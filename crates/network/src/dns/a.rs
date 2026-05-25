//! Host address record (A / AAAA).

use std::net::IpAddr;

/// A resolved host address (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRecord(pub IpAddr);
