# building stage
FROM rust:1.67 as build

WORKDIR /app

COPY . . 

RUN cargo build --release

# production stage
FROM debian:stable-slim
COPY --from=build /app/target/release/quibble .

CMD [ "./quibble" ]

