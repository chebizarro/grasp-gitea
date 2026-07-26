FROM golang:1.25-alpine AS build
ARG BUILD_TAGS=""
RUN apk add --no-cache build-base git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=gitauth,target=/root/.netrc go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "${BUILD_TAGS}" -o /out/grasp-bridge ./cmd/grasp-bridge
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/grasp-pre-receive ./cmd/grasp-pre-receive

FROM alpine:3.20
# Hive-CI remains experimental: this runtime intentionally does not bundle
# act or a privileged container runtime. See README.md before enabling it.
RUN apk add --no-cache ca-certificates git sqlite-libs
WORKDIR /app
COPY --from=build /out/grasp-bridge /usr/local/bin/grasp-bridge
COPY --from=build /out/grasp-pre-receive /usr/local/bin/grasp-pre-receive
ENTRYPOINT ["grasp-bridge"]
