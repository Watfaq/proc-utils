fn main() {
    #[cfg(target_os = "macos")]
    {
        println!("cargo::rerun-if-changed=src/darwin/bridge.h");
        let bindings = bindgen::builder()
            .header("src/darwin/bridge.h")
            .clang_args(&[
                "-I",
                "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/",
            ])
            .generate()
            .expect("unabled to generate libproc bindings");

        let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("darwin.rs"))
            .expect("Couldn't write bindings!");
    }
}
