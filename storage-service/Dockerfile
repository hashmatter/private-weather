FROM rust:1.43

WORKDIR /usr/src
COPY . .

RUN cargo build

CMD ["./target/debug/pir-storage-service"]
