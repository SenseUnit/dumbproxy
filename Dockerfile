FROM golang AS build

WORKDIR /go/src/github.com/Snawoot/dumbproxy
COPY . .
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-s -w -extldflags "-static"'
ADD https://curl.haxx.se/ca/cacert.pem /certs.crt
RUN chmod 0644 /certs.crt

FROM scratch AS arrange
COPY --from=build /go/src/github.com/Snawoot/dumbproxy/dumbproxy /
COPY --from=build /certs.crt /etc/ssl/certs/ca-certificates.crt

FROM scratch
COPY --from=arrange / /
USER 9999:9999
EXPOSE 8080/tcp
ENTRYPOINT ["/dumbproxy", "-bind-address", ":8080"]
