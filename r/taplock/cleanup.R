# This R script reverses the changes made during package build preparation.
# It removes the copied Rust files and resets the Cargo.toml substitutions
# back to their original state.

# Reset Cargo.toml
cargo_toml <- "src/rust/Cargo.toml"
lines <- readLines(cargo_toml)
writeLines(
  gsub("../", "../../../../", lines, fixed = TRUE),
  cargo_toml
)

# Remove copied files
unlink(
  c(
    "src/rs",
    "src/Cargo.toml",
    "src/Cargo.lock"
  ),
  recursive = TRUE
)

# Reset workspace Cargo.toml (if it still exists)
top_cargo_toml <- "src/Cargo.toml"
if (file.exists(top_cargo_toml)) {
  lines <- readLines(top_cargo_toml)
  # change the path back to the original
  lines <- gsub("rust", "r/taplock/src/rust", lines, fixed = TRUE)
  writeLines(lines, top_cargo_toml)
}

unlink(
  c(
    "src/rust/vendor",
    "src/rust/vendor.tar.xz",
    "src/rust/vendor-config.toml"
  ),
  recursive = TRUE
)
