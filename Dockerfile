FROM golang:1.18-alpine as builder

WORKDIR /src/secret-diver

ADD . .

RUN go build

FROM alpine:latest

COPY --from=builder /src/secret-diver/secret-diver /go/bin/secret-diver

WORKDIR /opt

ENTRYPOINT ["/go/bin/secret-diver"]
