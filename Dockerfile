FROM golang:1.17 AS builder
RUN apt-get update

# add local repo into the builder
ADD . /opt/build
WORKDIR /opt/build

# build the binary there
RUN CGO_ENABLED=0 go build promexport/cmd/export.go

# begin new container
FROM alpine
WORKDIR /

# copy binary from builder to your desired location
COPY --from=builder /opt/build/export .
ENTRYPOINT /export $0
