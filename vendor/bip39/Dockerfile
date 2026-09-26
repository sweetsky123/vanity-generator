FROM rust:1.29.0
WORKDIR /usr/src/bip39
COPY . .
# RUN --mount=type=cache,target=/usr/local/cargo/registry \
#     --mount=type=cache,target=/home/root/app/target \
#     cargo test --features=rand,all-languages
RUN cargo test --features=rand,all-languages
CMD ["/bin/bash"]
