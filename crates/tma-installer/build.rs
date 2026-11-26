use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=TMA_PAYLOAD_DIR");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("payloads.rs");
    let Some(directory) = std::env::var_os("TMA_PAYLOAD_DIR").map(PathBuf::from) else {
        std::fs::write(output, "pub static PAYLOADS: &[(&str, &[u8])] = &[];\n").unwrap();
        return;
    };
    let mut source = String::from("pub static PAYLOADS: &[(&str, &[u8])] = &[\n");
    for name in [
        "tma-agent.exe",
        "tma-relay.exe",
        "tma-parser.exe",
        "tma-doctor.exe",
    ] {
        let path = directory.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("reading embedded payload {}: {error}", path.display()));
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&bytes).unwrap();
        let compressed = encoder.finish().unwrap();
        source.push_str(&format!("    ({name:?}, &{compressed:?}),\n"));
    }
    source.push_str("];\n");
    std::fs::write(output, source).unwrap();
}
