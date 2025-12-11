
build-r-wrappers:
    cd r/rdaccess/src/rust && cargo build --release
    cd r/rdaccess && Rscript -e "rextendr::document()"

test-r-wrappers:
    just r/rdaccess/test

install-r-wrappers:
    just r/rdaccess/install

document-r-wrappers:
    just r/rdaccess/document
