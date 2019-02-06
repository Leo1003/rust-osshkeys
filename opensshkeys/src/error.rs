use std::error;
use std::fmt::Display;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: &str) -> Error {
        Error {
            message: String::from(message)
        }
    }
}