FROM golang:1.17.2-alpine3.13 as builder

#RUN apk update
RUN apk add git make build-base

ADD . /src/secret-diver

WORKDIR /src/secret-diver

RUN make build

RUN chmod +x /src/secret-diver/secret-diver

FROM alpine
COPY --from=builder /src/secret-diver/secret-diver /go/bin/secret-diver

WORKDIR /_cider_src_
CMD ["-image", "dir:/_cider_src_"]
ENTRYPOINT ["/go/bin/secret-diver"]
