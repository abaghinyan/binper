use std::fmt;

use serde_json;

use crate::pe::pe::PE;

impl fmt::Display for PE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}", serde_json::to_string_pretty(&self).unwrap())
    }
}