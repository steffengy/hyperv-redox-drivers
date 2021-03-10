//! # AML
//!
//! Code to parse and execute ACPI Machine Language tables.

use std::collections::HashMap;

use syscall::io::{Io, Pio};

use crate::acpi::{AcpiContext, AmlContainingTable, Sdt, SdtHeader};

#[macro_use]
mod parsermacros;

mod namespace;
mod termlist;
mod namespacemodifier;
mod pkglength;
mod namestring;
mod namedobj;
mod dataobj;
mod type1opcode;
mod type2opcode;
mod parser;

use self::parser::AmlExecutionContext;
use self::termlist::parse_term_list;
pub use self::namespace::AmlValue;

#[derive(Debug)]
pub enum AmlError {
    AmlParseError(&'static str),
    AmlInvalidOpCode,
    AmlValueError,
    AmlDeferredLoad,
    AmlFatalError(u8, u16, AmlValue),
    AmlHardFatal
}

pub fn parse_aml_table(sdt: impl AmlContainingTable) -> Result<Vec<String>, AmlError> {
    parse_aml_with_scope(sdt, "\\".to_owned())
}

pub fn parse_aml_with_scope(sdt: impl AmlContainingTable, scope: String) -> Result<Vec<String>, AmlError> {
    let data = sdt.aml();
    let mut ctx = AmlExecutionContext::new(scope);

    parse_term_list(data, &mut ctx)?;

    Ok(ctx.namespace_delta)
}

pub fn is_aml_table(sdt: &SdtHeader) -> bool {
    if &sdt.signature == b"DSDT" || &sdt.signature == b"SSDT" {
        true
    } else {
        false
    }
}

fn init_aml_table(sdt: impl AmlContainingTable) {
    match parse_aml_table(sdt) {
        Ok(_) => println!(": Parsed"),
        Err(AmlError::AmlParseError(e)) => println!(": {}", e),
        Err(AmlError::AmlInvalidOpCode) => println!(": Invalid opcode"),
        Err(AmlError::AmlValueError) => println!(": Type constraints or value bounds not met"),
        Err(AmlError::AmlDeferredLoad) => println!(": Deferred load reached top level"),
        Err(AmlError::AmlFatalError(_, _, _)) => {
            println!(": Fatal error occurred");
            // TODO
            return;
        },
        Err(AmlError::AmlHardFatal) => {
            println!(": Fatal error occurred");
            // TODO
            return;
        }
    }
}
fn init_namespace(context: &AcpiContext) -> HashMap<String, AmlValue> {
    let dsdt = context.dsdt().expect("could not find any DSDT");

    log::info!("Found DSDT.");
    init_aml_table(dsdt);

    let ssdts = context.ssdts();

    for ssdt in ssdts {
        print!("Found SSDT.");
        init_aml_table(ssdt);
    }

    todo!()
}

pub fn set_global_s_state(context: &AcpiContext, state: u8) {
    if state != 5 {
        return
    }
    let fadt = match context.fadt() {
        Some(fadt) => fadt,
        None =>  {
            log::error!("Cannot set global S-state due to missing FADT.");
            return;
        }
    };

    let port = fadt.pm1a_control_block as u16;
    let mut val = 1 << 13;

    let namespace = match context.namespace() {
        Some(namespace) => namespace,
        None => {
            log::error!("Cannot set global S-state due to missing ACPI namespace");
            return;
        }
    };

    let s5 = match namespace.get("\\_S5") {
        Some(s5) => s5,
        None => {
            log::error!("Cannot set global S-state due to missing \\_S5");
            return;
        }
    };
    let p = match s5.get_as_package() {
        Ok(package) => package,
        Err(error) => {
            log::error!("Cannot set global S-state due to \\_S5 not being a package: {:?}", error);
            return;
        }
    };

    let slp_typa = p[0].get_as_integer().expect("SLP_TYPa is not an integer");
    let slp_typb = p[1].get_as_integer().expect("SLP_TYPb is not an integer");

    log::info!("Shutdown SLP_TYPa {:X}, SLP_TYPb {:X}", slp_typa, slp_typb);
    val |= slp_typa as u16;

    log::info!("Shutdown with ACPI outw(0x{:X}, 0x{:X})", port, val);
    Pio::<u16>::new(port).write(val);
}
