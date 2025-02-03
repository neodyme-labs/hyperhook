//! Module containing platform-specific functions for handling modules on Unix systems.

use goblin::elf;
use log::{trace, warn};
use phdrs::objects;

// use std::{collections::HashMap, path::PathBuf, sync::Mutex};
// use once_cell::sync::Lazy;

// static MODULE_CACHE: Lazy<Mutex<HashMap<String, usize>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Represents a loaded object and provides methods to get symbol addresses and other information from the module.
struct Module {
    object: phdrs::Object,
    path: std::path::PathBuf,
}

impl Module {
    /// Get a loaded Object by name. Use an empty string "" to get the main module.
    fn new(module_name: &str) -> Option<Module> {
        for object in objects() {
            let obj_name_str = String::from_utf8_lossy(object.name().to_bytes()).to_string();
            trace!("Got module name via phdr: {}", obj_name_str.as_str());

            if obj_name_str.contains(module_name) {
                let path = match module_name.is_empty() {
                    true => std::env::current_exe().unwrap(),
                    false => std::path::PathBuf::from(obj_name_str),
                };

                return Some(Module { object, path });
            }
        }
        None
    }

    /// Get the address of a symbol in a module.
    fn get_symbol_address(self, symbol: &str) -> Option<usize> {
        trace!("Reading module {} from disk", self.path.display());
        let buffer = std::fs::read(self.path).expect("Failed to read module from disk");
        let elf = elf::Elf::parse(&buffer).expect("Failed to parse module");

        if let Some(offset) = get_offset(&elf.dynsyms, &elf.dynstrtab, symbol) {
            trace!(
                "Found function {symbol} at 0x{:016x}",
                offset + self.object.addr() as usize
            );
            return Some(offset + self.object.addr() as usize);
        }

        if let Some(offset) = get_offset(&elf.syms, &elf.strtab, symbol) {
            trace!(
                "Found function {symbol} at 0x{:016x}",
                offset + self.object.addr() as usize
            );
            return Some(offset + self.object.addr() as usize);
        }
        warn!("Symbol {symbol} not found");
        None
    }
}

fn get_offset(
    symtab: &goblin::elf::Symtab,
    strtab: &goblin::strtab::Strtab,
    function_name: &str,
) -> Option<usize> {
    symtab
        .iter()
        .find(|sym| {
            if let Some(name_bytes) = strtab.get_at(sym.st_name) {
                if let Ok(name) = std::str::from_utf8(name_bytes.as_bytes()) {
                    return name.trim_end_matches('\0') == function_name;
                }
            }
            false
        })
        .map(|sym| sym.st_value as usize)
}

/// Get the address of a symbol in a module. Use "" for the main module.
pub fn get_symbol_address(module_name: &str, function_name: &str) -> Option<usize> {
    trace!("Searching for function {function_name} in module {module_name}");

    if let Some(module) = Module::new(module_name) {
        module.get_symbol_address(function_name)
    } else {
        warn!("Module {module_name} not found");
        None
    }
}

/// Get the address of a module. Use "" for the main module.
pub fn get_module_address(module_name: &str) -> Option<usize> {
    let main_module = Module::new(module_name);
    match main_module {
        Some(module) => Some(module.object.addr() as usize),
        _ => None,
    }
}

/// Get the address of the main module.
pub fn get_main_module_address() -> Option<usize> {
    get_module_address("")
}
