fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .file_descriptor_set_path("target/auth_descriptor.bin")
        .compile_protos(&["protos/auth.proto"], &["proto"])?;
    Ok(())
}
