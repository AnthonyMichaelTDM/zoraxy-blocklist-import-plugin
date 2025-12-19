.PHONY: all
SRC_FILES = $(filter-out build/, $(wildcard src/*.rs))

all: build-musl

build-musl:
	cargo zigbuild --target x86_64-unknown-linux-musl --release
	mkdir -p ./build/plugins/zoraxy-blocklist-import-plugin/
	cp ./target/x86_64-unknown-linux-musl/release/zoraxy-blocklist-import-plugin ./build/plugins/zoraxy-blocklist-import-plugin/zoraxy-blocklist-import-plugin

