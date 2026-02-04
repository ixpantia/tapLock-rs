
build-r-wrappers:
    cd r/taplock/src/rust && cargo build --release
    cd r/taplock && Rscript -e "rextendr::document()"

test-r-wrappers:
    just r/taplock/test

install-r-wrappers:
    just r/taplock/install

document-r-wrappers:
    just r/taplock/document
