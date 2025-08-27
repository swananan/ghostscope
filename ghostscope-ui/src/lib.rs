pub fn hello() -> String {
    format!("UI: {}", ghostscope_frontend::hello())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "UI: Frontend: Hello from ghostscope-compiler!");
    }
}
