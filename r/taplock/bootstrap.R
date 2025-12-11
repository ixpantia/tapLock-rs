# R builds a package by copying only the sources under the directory of the R
# package, which means it cannot refer to the Rust files above the directory.
# So, this R script copies the necessary Rust crates under the R package dir.
# Note that, this is not a standard mechanism of R, but is only invoked by
# pkgbuild (cf. https://github.com/r-lib/pkgbuild/pull/157)

# Tweak Cargo.toml
cargo_toml <- "src/rust/Cargo.toml"
lines <- readLines(cargo_toml)
writeLines(
  gsub("../../../../", "../", lines, fixed = TRUE),
  cargo_toml
)

file.copy(
  c(
    "../../rs",
    "../../Cargo.toml",
    "../../Cargo.lock"
  ),
  "src/",
  recursive = TRUE
)

# Tweak workspace Cargo.toml
top_cargo_toml <- "src/Cargo.toml"
lines <- readLines(top_cargo_toml)
# change the path to the R package's Rust code
lines <- gsub("r/ixaccess/src/rust", "rust", lines, fixed = TRUE)
lines <- gsub('"py/ixaccess",', "", lines, fixed = TRUE)
print(lines)
# remove unnecessary workspace members
writeLines(lines, top_cargo_toml)

rextendr::vendor_pkgs()
