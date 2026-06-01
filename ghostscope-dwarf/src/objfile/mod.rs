//! Loaded object file: complete DWARF data for a single binary

pub(crate) mod function_lookup;
pub(crate) mod globals;
pub(crate) mod loaded;
pub(crate) mod loading;
pub(crate) mod source_location;
pub(crate) mod unwind;
pub(crate) mod variables;

pub(crate) use loaded::LoadedObjfile;
pub(crate) use unwind::ModuleUnwindInfo;
