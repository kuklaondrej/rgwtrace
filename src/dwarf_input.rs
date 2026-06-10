use std::path::PathBuf;

use anyhow::Result;

use crate::{dwarf_json::DwarfInfo, dwarf_native};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DwarfInput {
    Json(PathBuf),
    Native(Vec<PathBuf>),
}

impl DwarfInput {
    pub fn json(path: impl Into<PathBuf>) -> Self {
        Self::Json(path.into())
    }

    pub fn native(paths: Vec<PathBuf>) -> Self {
        Self::Native(paths)
    }

    pub fn description(&self) -> String {
        match self {
            Self::Json(path) => path.display().to_string(),
            Self::Native(paths) => paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    pub fn load(&self) -> Result<DwarfInfo> {
        match self {
            Self::Json(path) => DwarfInfo::from_path(path),
            Self::Native(paths) => dwarf_native::from_paths(paths),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_json_input_path() {
        let input = DwarfInput::json("ceph.json");

        assert_eq!(input.description(), "ceph.json");
    }

    #[test]
    fn describes_native_input_paths() {
        let input = DwarfInput::native(vec!["a".into(), "b".into()]);

        assert_eq!(input.description(), "a,b");
    }
}
