fn main() {
    // Compile the resource script that embeds the manifest.
    embed_resource::compile("app.rc", embed_resource::NONE);
}
