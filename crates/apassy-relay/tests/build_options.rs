//! The SQLCipher build of this crate has the flags that the core vault requires
//! (`.cargo/config.toml`). Without them the team vault and the core refuse to open.

#[test]
fn sqlcipher_is_built_without_extensions_uri_or_lookaside() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let mut statement = conn.prepare("PRAGMA compile_options").unwrap();
    let options: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        options.iter().any(|o| o == "OMIT_LOAD_EXTENSION"),
        "{options:?}"
    );
    assert!(
        options.iter().any(|o| o == "DEFAULT_LOOKASIDE=0,0"),
        "{options:?}"
    );
    assert!(
        !options.iter().any(|o| o == "ENABLE_LOAD_EXTENSION"),
        "{options:?}"
    );
    assert!(
        !options.iter().any(|o| o.starts_with("USE_URI")),
        "{options:?}"
    );
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .unwrap();
    assert!(!version.is_empty(), "SQLCipher is linked");
}
