//! Embeds the application icon into the Windows executables.

fn main() {
    println!("cargo:rerun-if-changed=assets/icons/doubleagent.ico");
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/icons/doubleagent.ico");
        if let Err(error) = resource.compile() {
            println!("cargo:warning=could not embed the application icon: {error}");
        }
    }
}
