use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::dwarf_json::DwarfInfo;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DwarfInput {
    Json(PathBuf),
}

impl DwarfInput {
    pub fn json(path: impl Into<PathBuf>) -> Self {
        Self::Json(path.into())
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Json(path) => path,
        }
    }

    pub fn load(&self) -> Result<DwarfInfo> {
        match self {
            Self::Json(path) => DwarfInfo::from_path(path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_json_input_path() {
        let input = DwarfInput::json("ceph.json");

        assert_eq!(input.path(), Path::new("ceph.json"));
    }
}
