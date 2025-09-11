FROM --platform=$BUILDPLATFORM golang AS build

ARG GIT_DESC=undefined

WORKDIR /go/src/github.com/SenseUnit/dumbproxy
COPY . .
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -a -tags netgo -ldflags '-s -w -extldflags "-static" -X main.version='"$GIT_DESC"
RUN mkdir /.dumbproxy

FROM scratch
COPY --from=build /go/src/github.com/SenseUnit/dumbproxy/dumbproxy /
COPY --from=build --chown=9999:9999 /.dumbproxy /.dumbproxy
USER 9999:9999
EXPOSE 8080/tcp
ENTRYPOINT ["/dumbproxy"]
CMD ["-bind-address", ":8080" ]

#FROM alpine AS alpine
#COPY --from=build /go/src/github.com/SenseUnit/dumbproxy/dumbproxy /
#COPY --from=build --chown=9999:9999 /.dumbproxy /.dumbproxy
#RUN apk add --no-cache tzdata
#USER 9999:9999
#EXPOSE 8080/tcp
#ENTRYPOINT ["/dumbproxy", "-bind-address", ":8080"]
