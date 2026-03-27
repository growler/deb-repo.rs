mod common;

use {
    common::ARCH,
    debrepo::Manifest,
    serde::{de::DeserializeOwned, Serialize},
};

fn manifest_with_env(items: &[(&str, &str)]) -> Manifest {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Manifest.toml");
    let mut manifest = Manifest::new(&path, ARCH, None);
    manifest
        .set_build_env(
            None,
            items
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
        )
        .expect("set build env");
    manifest
}

fn roundtrip<T>(value: &T) -> T
where
    T: Serialize + DeserializeOwned,
{
    serde_json::from_str(&serde_json::to_string(value).expect("serialize")).expect("deserialize")
}

fn decode_like<T>(value: &T, src: &str) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned,
{
    let _ = value;
    serde_json::from_str(src)
}

#[test]
fn kvlist_accessors_preserve_order_and_lookup() {
    let manifest = manifest_with_env(&[("FOO", "bar"), ("BAR", "baz"), ("BAZ", "qux")]);
    let env = manifest.spec_build_env(None).expect("build env");

    assert!(!env.is_empty());
    assert_eq!(env.len(), 3);
    assert_eq!(
        env.iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAR".to_string(), "baz".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ]
    );
    assert_eq!(
        env.iter_keys().collect::<Vec<_>>(),
        vec!["FOO", "BAR", "BAZ"]
    );
    assert_eq!(
        env.iter_values().map(String::as_str).collect::<Vec<_>>(),
        vec!["bar", "baz", "qux"]
    );
    assert_eq!(env.get("BAR").map(String::as_str), Some("baz"));
    assert_eq!(env.get("MISSING"), None);
    assert_eq!(env.entry_at(1).0, "BAR");
    assert_eq!(env.entry_at(1).1, "baz");
    assert_eq!(env.key_at(2), "BAZ");
    assert_eq!(env.value_at(0), "bar");
    assert!(env.contains_key("FOO"));
    assert!(!env.contains_key("missing"));
    assert_eq!(env[2], "qux");
}

#[test]
fn kvlist_mutation_helpers_update_in_place() {
    let manifest = manifest_with_env(&[("FOO", "bar"), ("BAR", "baz"), ("BAZ", "qux")]);
    let mut env = manifest.spec_build_env(None).expect("build env");

    for (key, value) in env.iter_mut() {
        if key == "FOO" {
            *value = "first".to_string();
        }
    }
    for value in env.iter_values_mut() {
        value.make_ascii_uppercase();
    }
    assert_eq!(env.entry_mut_at(1).0, "BAR");
    *env.entry_mut_at(1).1 = "SECOND".to_string();
    *env.value_mut_at(2) = "THIRD".to_string();
    env.set_at(0, "ALPHA".to_string(), "FIRST".to_string());
    env[1] = "UPDATED".to_string();

    assert_eq!(
        env.iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("ALPHA".to_string(), "FIRST".to_string()),
            ("BAR".to_string(), "UPDATED".to_string()),
            ("BAZ".to_string(), "THIRD".to_string()),
        ]
    );
}

#[test]
fn kvlist_consuming_helpers_remove_and_drain_in_order() {
    let manifest = manifest_with_env(&[("FOO", "bar"), ("BAR", "baz"), ("BAZ", "qux")]);
    let mut env = manifest.spec_build_env(None).expect("build env");

    let removed = env.remove_at(1);
    assert_eq!(removed, ("BAR".to_string(), "baz".to_string()));
    let drained = env.drain().collect::<Vec<_>>();
    assert!(env.is_empty());
    assert_eq!(
        drained,
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ]
    );

    let mut env = manifest.spec_build_env(None).expect("build env");
    let taken = std::mem::take(&mut env);
    assert!(env.is_empty());
    assert_eq!(
        taken.into_iter().collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAR".to_string(), "baz".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ]
    );
}

#[test]
fn kvlist_display_debug_and_serde_roundtrip() {
    let manifest = manifest_with_env(&[("FOO", "bar"), ("BAR", "baz")]);
    let env = manifest.spec_build_env(None).expect("build env");

    assert_eq!(format!("{env}"), "FOO: bar\nBAR: baz\n");
    let debug = format!("{env:?}");
    assert!(debug.starts_with("{"));
    assert!(debug.contains("\"FOO\": \"bar\""));
    assert!(debug.contains("\"BAR\": \"baz\""));

    let json = serde_json::to_string(&env).expect("serialize");
    assert_eq!(json, r#"{"FOO":"bar","BAR":"baz"}"#);

    let decoded = roundtrip(&env);
    assert_eq!(
        decoded
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAR".to_string(), "baz".to_string()),
        ]
    );
}

#[test]
fn kvlist_deserialize_rejects_duplicate_keys_and_non_maps() {
    let manifest = manifest_with_env(&[("FOO", "bar")]);
    let env = manifest.spec_build_env(None).expect("build env");

    let decoded = decode_like(&env, r#"{"FOO":"bar","BAR":"baz"}"#).expect("decode");
    assert_eq!(decoded.key_at(0), "FOO");
    assert_eq!(decoded.key_at(1), "BAR");

    let err = decode_like(&env, r#"{"FOO":"bar","FOO":"baz"}"#).expect_err("duplicate keys");
    assert!(err.to_string().contains("duplicate item name: FOO"));

    let err = decode_like(&env, "123").expect_err("non-map input");
    assert!(err.to_string().contains("a map of items"));
}
