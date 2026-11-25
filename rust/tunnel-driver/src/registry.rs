//! Driver registry for Rust applications.

use std::fmt;

use crate::driver::TunnelDriver;
use crate::etherip::EtherIpDriver;

/// A small ordered registry of tunnel drivers.
#[derive(Default)]
pub struct DriverRegistry {
    drivers: Vec<Box<dyn TunnelDriver>>,
}

impl fmt::Debug for DriverRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.drivers.iter().map(|d| d.name()))
            .finish()
    }
}

impl DriverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry with the RFC 3378 drivers pre-registered.
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        r.register(Box::new(EtherIpDriver::etherip6()))
            .expect("fresh registry");
        r.register(Box::new(EtherIpDriver::etherip()))
            .expect("fresh registry");
        r
    }

    /// Add a driver.  Returns an error if the name is already registered.
    pub fn register(&mut self, driver: Box<dyn TunnelDriver>) -> Result<(), String> {
        if driver.name().is_empty() {
            return Err("driver name must not be empty".into());
        }
        if self.drivers.iter().any(|d| d.name() == driver.name()) {
            return Err(format!("driver '{}' already registered", driver.name()));
        }
        self.drivers.push(driver);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&dyn TunnelDriver> {
        self.drivers
            .iter()
            .find(|d| d.name() == name)
            .map(|d| d.as_ref())
    }

    pub fn len(&self) -> usize {
        self.drivers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.drivers.iter().map(|d| d.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_names_are_rejected() {
        let mut r = DriverRegistry::with_builtins();
        assert!(r.get("etherip6-rs").is_some());
        assert!(r.register(Box::new(EtherIpDriver::etherip6())).is_err());
        assert_eq!(r.len(), 2);
    }
}
