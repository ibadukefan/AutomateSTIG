FROM rust:1.94-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static
WORKDIR /app
COPY . .
RUN cargo build --release --bin automatestig-gui

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/automatestig-gui /usr/local/bin/
COPY --from=builder /app/content/check_packs /app/content/check_packs
EXPOSE 8080
ENV RUST_LOG=info \
    AUTOMATESTIG_BIND=0.0.0.0
CMD ["automatestig-gui"]
