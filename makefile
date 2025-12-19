.PHONY: all
SRC_FILES = $(filter-out build/, $(wildcard src/*.rs))

all: test

# Build the project and copy the output to the docker containers plugin folder
test:
	cargo zigbuild --target x86_64-unknown-linux-musl --release
	mkdir -p ./build/plugins/zoraxy-blocklist-manager/
	cp ./target/x86_64-unknown-linux-musl/release/zoraxy-blocklist-manager ./build/plugins/zoraxy-blocklist-manager/zoraxy-blocklist-manager
