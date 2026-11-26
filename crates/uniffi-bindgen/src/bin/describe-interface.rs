//! Prints the interface a UniFFI library exports, one declaration per line,
//! as UniFFI itself reads it from the library: the same metadata the Kotlin
//! and Swift generators work from.
//!
//! ```text
//! cargo run -p uniffi-bindgen --bin describe-interface -- <libsolana_thin_ffi>
//! ```
//!
//! `scripts/bindings.sh` compares the output with
//! `crates/solana-thin-ffi/interface.txt`, so that a change to what foreign
//! callers see shows up in review as a change to that file.

use anyhow::{bail, Context, Result};
use camino::Utf8PathBuf;
use uniffi_bindgen::interface::{Argument, AsType, Type};
use uniffi_bindgen::{BindgenLoader, BindgenPaths, GlobalConfig};

/// A type as the listing spells it. Anything this binding does not use yet
/// falls through to UniFFI's own name for it.
fn spell(ty: &Type) -> String {
    match ty {
        Type::UInt8 => "u8".into(),
        Type::UInt16 => "u16".into(),
        Type::UInt32 => "u32".into(),
        Type::UInt64 => "u64".into(),
        Type::Int8 => "i8".into(),
        Type::Int16 => "i16".into(),
        Type::Int32 => "i32".into(),
        Type::Int64 => "i64".into(),
        Type::Boolean => "bool".into(),
        Type::String => "string".into(),
        Type::Bytes => "bytes".into(),
        Type::Optional { inner_type } => format!("{}?", spell(inner_type)),
        Type::Sequence { inner_type } => format!("[{}]", spell(inner_type)),
        Type::Object { name, .. } | Type::Record { name, .. } | Type::Enum { name, .. } => {
            name.clone()
        }
        other => format!("{other:?}"),
    }
}

fn fields<T: AsType>(fields: &[T], name: impl Fn(&T) -> &str) -> String {
    let fields: Vec<_> = fields
        .iter()
        .map(|field| format!("{}: {}", name(field), spell(&field.as_type())))
        .collect();
    fields.join(", ")
}

/// `name(arguments) -> returned throws error`, leaving out what is absent.
fn signature(
    name: &str,
    arguments: Vec<&Argument>,
    returned: Option<&Type>,
    throws: Option<&Type>,
) -> String {
    let arguments: Vec<Argument> = arguments.into_iter().cloned().collect();
    let mut line = format!("{name}({})", fields(&arguments, Argument::name));
    if let Some(returned) = returned {
        line += &format!(" -> {}", spell(returned));
    }
    if let Some(error) = throws {
        line += &format!(" throws {}", spell(error));
    }
    line
}

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let (Some(library), None) = (arguments.next(), arguments.next()) else {
        bail!("usage: describe-interface <library>");
    };
    let library = Utf8PathBuf::from(library);
    let loader = BindgenLoader::new(BindgenPaths::default(), GlobalConfig::default());
    let metadata = loader
        .load_metadata(&library)
        .with_context(|| format!("reading UniFFI metadata from {library}"))?;
    let interfaces = loader.load_cis(metadata)?;
    if interfaces.is_empty() {
        bail!("{library} exports no UniFFI interface");
    }

    for interface in &interfaces {
        println!("namespace {}", interface.namespace());
        for function in interface.function_definitions() {
            let line = signature(
                function.name(),
                function.arguments(),
                function.return_type(),
                function.throws_type(),
            );
            println!("function {line}");
        }
        for record in interface.record_definitions() {
            println!("record {}", record.name());
            for field in record.fields() {
                println!("  {}: {}", field.name(), spell(&field.as_type()));
            }
        }
        for definition in interface.enum_definitions() {
            println!("enum {}", definition.name());
            for variant in definition.variants() {
                if variant.has_fields() {
                    let inside = fields(variant.fields(), |field| field.name());
                    println!("  {} {{ {inside} }}", variant.name());
                } else {
                    println!("  {}", variant.name());
                }
            }
        }
        for object in interface.object_definitions() {
            println!("object {}", object.name());
            let made = Type::Object {
                module_path: String::new(),
                name: object.name().to_owned(),
                imp: *object.imp(),
            };
            for constructor in object.constructors() {
                let line = signature(
                    constructor.name(),
                    constructor.arguments(),
                    Some(&made),
                    constructor.throws_type(),
                );
                println!("  constructor {line}");
            }
            for method in object.methods() {
                let line = signature(
                    method.name(),
                    method.arguments(),
                    method.return_type(),
                    method.throws_type(),
                );
                println!("  method {line}");
            }
        }
    }
    Ok(())
}
