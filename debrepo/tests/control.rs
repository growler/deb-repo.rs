use {
    debrepo::{
        control::{
            ControlFile, ControlParser, ControlStanza, Field, FindFields, MutableControlField,
            MutableControlFile, MutableControlStanza, ParseError,
        },
        PackageOrigin, Packages,
    },
    serde::{Deserialize, Serialize},
};

fn sample_stanza_src() -> &'static str {
    "Package: demo
Architecture: amd64
Version: 1.0
Description:
 Demo package
"
}

#[derive(Serialize, Deserialize)]
struct StanzaWire {
    stanza: MutableControlStanza,
}

#[test]
fn parse_error_formats_and_converts_to_io_error() {
    let static_err = ParseError::from("static parse error");
    assert_eq!(static_err.to_string(), "static parse error");

    let owned_err = ParseError::from("owned parse error".to_string());
    assert_eq!(owned_err.to_string(), "owned parse error");

    let io_err: std::io::Error = owned_err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(io_err.to_string(), "owned parse error");
}

#[test]
fn control_fields_display_and_trait_accessors_cover_inline_and_multiline_values() {
    let mut parser = ControlParser::new("Package: demo\nDescription:\n Long text\n");
    let package = parser.field().unwrap().unwrap();
    assert!(package.is_a("package"));
    assert_eq!(package.name(), "Package");
    assert_eq!(package.value(), "demo");
    assert_eq!(package.to_string(), "Package: demo\n");

    let description = parser.field().unwrap().unwrap();
    assert!(description.is_a("description"));
    assert_eq!(description.name(), "Description");
    assert_eq!(description.value(), "\n Long text");
    assert_eq!(description.to_string(), "Description:\n Long text\n");

    let mut mutable = MutableControlField::new("Homepage", "https://example.invalid");
    assert!(mutable.is_a("homepage"));
    assert_eq!(mutable.name(), "Homepage");
    assert_eq!(mutable.value(), "https://example.invalid");
    assert_eq!(mutable.to_string(), "Homepage: https://example.invalid\n");

    mutable.set("\n Detail line");
    assert_eq!(mutable.value(), "\n Detail line");
    assert_eq!(mutable.to_string(), "Homepage:\n Detail line\n");

    let from_owned = MutableControlField::from(package);
    assert_eq!(from_owned.name(), "Package");
    assert_eq!(from_owned.value(), "demo");

    let from_borrowed = MutableControlField::from(&description);
    assert_eq!(from_borrowed.name(), "Description");
    assert_eq!(from_borrowed.value(), "\n Long text");
}

#[test]
fn control_stanza_roundtrips_and_rejects_empty_input() {
    let stanza = ControlStanza::parse(sample_stanza_src()).unwrap();
    assert_eq!(stanza.len(), sample_stanza_src().len());
    assert_eq!(stanza.field("package"), Some("demo"));
    assert_eq!(stanza.field("missing"), None);

    let fields: Vec<_> = stanza.fields().map(|field| field.name()).collect();
    assert_eq!(
        fields,
        vec!["Package", "Architecture", "Version", "Description"]
    );
    assert_eq!(stanza.to_string(), sample_stanza_src());

    let err = ControlStanza::parse("\n").unwrap_err();
    assert_eq!(err.to_string(), "Empty control stanza");
}

#[test]
fn mutable_stanza_mutation_methods_cover_insert_update_remove_retain_and_package_name() {
    let empty = MutableControlStanza::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let mut stanza = MutableControlStanza::parse(sample_stanza_src()).unwrap();
    assert!(!stanza.is_empty());
    assert_eq!(stanza.field("architecture"), Some("amd64"));

    stanza
        .set("Architecture", "arm64".to_string())
        .set("Priority", "required".to_string())
        .set("X-Extra", "kept".to_string());
    assert_eq!(stanza.field("Architecture"), Some("arm64"));
    assert_eq!(stanza.field("Priority"), Some("required"));
    assert_eq!(stanza.package_name().unwrap(), "demo_1.0_arm64");

    stanza.remove("Priority").remove("Not-There");
    assert_eq!(stanza.field("Priority"), None);

    stanza.retain(|field| !field.is_a("X-Extra"));
    assert_eq!(stanza.field("X-Extra"), None);

    let field_names: Vec<_> = stanza
        .fields()
        .map(|field| field.name().into_owned())
        .collect();
    assert_eq!(
        field_names,
        vec!["Package", "Architecture", "Version", "Description"]
    );

    let copied = MutableControlStanza::from(&ControlStanza::parse(sample_stanza_src()).unwrap());
    assert_eq!(copied.to_string(), sample_stanza_src());

    let mut missing = MutableControlStanza::new();
    missing.set("Package", "demo".to_string());
    missing.set("Version", "1.0".to_string());
    assert_eq!(
        missing.package_name().unwrap_err().to_string(),
        "Architecture"
    );
}

#[test]
fn mutable_stanza_sorting_covers_custom_sort_and_dpkg_order_tiebreaks() {
    let mut stanza = MutableControlStanza::new();
    stanza.set("z-last", "1".to_string());
    stanza.set("alpha", "2".to_string());
    stanza.set("Beta", "3".to_string());

    stanza.sort_fields_by_name(|left, right| right.cmp(left));
    let sorted: Vec<_> = stanza
        .fields()
        .map(|field| field.name().into_owned())
        .collect();
    assert_eq!(sorted, vec!["z-last", "alpha", "Beta"]);

    let mut dpkg = MutableControlStanza::new();
    dpkg.set("z-last", "1".to_string());
    dpkg.set("description", "\n body".to_string());
    dpkg.set("Package", "demo".to_string());
    dpkg.set("Version", "1.0".to_string());
    dpkg.set("architecture", "amd64".to_string());
    dpkg.set("beta", "2".to_string());
    dpkg.set("Alpha", "3".to_string());

    dpkg.sort_fields_deb_order();
    let names: Vec<_> = dpkg
        .fields()
        .map(|field| field.name().into_owned())
        .collect();
    assert_eq!(
        names,
        vec![
            "Package",
            "Version",
            "architecture",
            "description",
            "Alpha",
            "beta",
            "z-last",
        ]
    );
}

#[test]
fn find_fields_supports_single_pair_triple_for_immutable_and_mutable_fields() {
    let stanza = ControlStanza::parse(sample_stanza_src()).unwrap();

    let package = stanza.fields().cloned().find_fields("Package").unwrap();
    assert_eq!(package, "demo");
    assert_eq!(
        stanza
            .fields()
            .cloned()
            .find_fields(("Package", "Version"))
            .unwrap(),
        ("demo", "1.0")
    );
    assert_eq!(
        stanza
            .fields()
            .cloned()
            .find_fields(("Architecture", "Package", "Version"))
            .unwrap(),
        ("amd64", "demo", "1.0")
    );
    assert_eq!(
        stanza.fields().cloned().find_fields("Missing").unwrap_err(),
        "Missing"
    );
    assert_eq!(
        stanza
            .fields()
            .cloned()
            .find_fields(("Package", "Missing"))
            .unwrap_err(),
        "Missing"
    );
    assert_eq!(
        stanza
            .fields()
            .cloned()
            .find_fields(("Missing-A", "Package", "Version"))
            .unwrap_err(),
        "Missing-A"
    );

    let mutable = MutableControlStanza::parse(sample_stanza_src()).unwrap();
    let borrowed = mutable.fields().find_fields("Version").unwrap();
    assert_eq!(borrowed, "1.0");
    assert_eq!(
        mutable
            .fields()
            .find_fields(("Package", "Architecture"))
            .unwrap(),
        ("demo".into(), "amd64".into())
    );
    assert_eq!(
        mutable
            .fields()
            .find_fields(("Architecture", "Package", "Version"))
            .unwrap(),
        ("amd64".into(), "demo".into(), "1.0".into())
    );

    let owned_fields = vec![
        MutableControlField::new("Package", "demo"),
        MutableControlField::new("Version", "1.0"),
    ];
    assert_eq!(
        owned_fields
            .clone()
            .into_iter()
            .find_fields(("Package", "Version"))
            .unwrap(),
        ("demo".into(), "1.0".into())
    );
    assert_eq!(
        owned_fields
            .into_iter()
            .find_fields("Architecture")
            .unwrap_err(),
        "Architecture"
    );
}

#[test]
fn mutable_stanza_serde_roundtrip_and_invalid_deserialize() {
    let wire = StanzaWire {
        stanza: MutableControlStanza::parse(sample_stanza_src()).unwrap(),
    };
    let json = serde_json::to_string(&wire).unwrap();
    assert!(json.contains("Package: demo"));

    let roundtrip: StanzaWire = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.stanza.to_string(), sample_stanza_src());

    let err = serde_json::from_str::<StanzaWire>(r#"{"stanza":""}"#)
        .err()
        .unwrap();
    assert!(err.to_string().contains("Empty control stanza"));
}

#[test]
fn mutable_control_file_collection_methods_and_bytes_conversion_work() {
    let mut file = MutableControlFile::default();
    assert_eq!(file.stanzas().count(), 0);

    let first = file.new_stanza();
    first.set("Package", "one".to_string());
    first.set("Architecture", "amd64".to_string());
    first.set("Version", "1.0".to_string());

    file.add(
        MutableControlStanza::parse("Package: two\nArchitecture: all\nVersion: 2.0\n").unwrap(),
    );
    assert_eq!(file.stanzas().count(), 2);

    file.set_at(
        1,
        MutableControlStanza::parse("Package: replacement\nArchitecture: all\nVersion: 3.0\n")
            .unwrap(),
    );
    assert_eq!(
        file.stanzas().nth(1).unwrap().field("Package"),
        Some("replacement")
    );

    let removed = file.remove_at(0);
    assert_eq!(removed.field("Package"), Some("one"));

    let mut collected: MutableControlFile =
        vec![
            MutableControlStanza::parse("Package: alpha\nArchitecture: amd64\nVersion: 1.0\n")
                .unwrap(),
        ]
        .into_iter()
        .collect();
    collected.extend(vec![MutableControlStanza::parse(
        "Package: beta\nArchitecture: all\nVersion: 2.0\n",
    )
    .unwrap()]);

    let rendered = collected.to_string();
    assert_eq!(
        rendered,
        "Package: alpha\nArchitecture: amd64\nVersion: 1.0\n\nPackage: beta\nArchitecture: all\nVersion: 2.0\n\n"
    );
    let bytes: Vec<u8> = collected.into();
    assert_eq!(String::from_utf8(bytes).unwrap(), rendered);
}

#[test]
fn mutable_control_file_try_from_packages_parses_valid_package_records() {
    let mut file = MutableControlFile::new();
    let stanza = file.new_stanza();
    stanza.set("Package", "demo".to_string());
    stanza.set("Architecture", "amd64".to_string());
    stanza.set("Version", "1.0".to_string());
    stanza.set("Filename", "pool/main/d/demo_1.0_amd64.deb".to_string());
    stanza.set("Size", "42".to_string());
    stanza.set(
        "SHA256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    );

    let packages = Packages::try_from(file).unwrap();
    assert_eq!(packages.origin(), PackageOrigin::Unknown);
    assert_eq!(packages.prio(), 500);
    assert_eq!(packages.packages().count(), 1);

    let package = packages.package_by_name("demo").unwrap();
    assert_eq!(package.name(), "demo");
    assert_eq!(package.arch(), "amd64");
    assert_eq!(package.version().unwrap().to_string(), "1.0");
}

#[test]
fn control_file_parse_and_display_cover_multi_stanza_files() {
    let src = "Package: one\nArchitecture: amd64\nVersion: 1.0\n\nPackage: two\nArchitecture: all\nVersion: 2.0\n";
    let file = ControlFile::parse(src).unwrap();
    assert_eq!(file.stanzas().count(), 2);
    assert_eq!(file.stanzas().next().unwrap().field("Package"), Some("one"));
    assert_eq!(
        file.stanzas().nth(1).unwrap().field("Architecture"),
        Some("all")
    );
    assert_eq!(
        file.to_string(),
        "Package: one\nArchitecture: amd64\nVersion: 1.0\nPackage: two\nArchitecture: all\nVersion: 2.0\n\n"
    );
}

#[test]
fn control_parser_handles_stanza_boundaries_blank_continuations_and_error_paths() {
    let mut parser = ControlParser::new(
        "Package: one\nArchitecture: amd64\n\nPackage: two\nArchitecture: all\n",
    );
    assert_eq!(parser.field().unwrap().unwrap().name(), "Package");
    assert_eq!(parser.field().unwrap().unwrap().name(), "Architecture");
    assert!(parser.field().unwrap().is_none());
    assert_eq!(parser.field().unwrap().unwrap().value(), "two");

    let mut parser = ControlParser::new("Field: value\n \nNext: item\n");
    assert_eq!(parser.field().unwrap().unwrap().value(), "value\n ");
    assert_eq!(parser.field().unwrap().unwrap().name(), "Next");

    let mut invalid_first = ControlParser::new("#Field: value\n");
    assert_eq!(
        invalid_first.field().unwrap_err().to_string(),
        "Invalid field name #Field: value\n"
    );

    let mut invalid_inner = ControlParser::new("Bad Name: value\n");
    assert_eq!(
        invalid_inner.field().unwrap_err().to_string(),
        "Invalid field name Bad Name: value\n"
    );

    let mut unterminated = ControlParser::new("Field");
    assert_eq!(
        unterminated.field().unwrap_err().to_string(),
        "unterminated field name Field"
    );
}
