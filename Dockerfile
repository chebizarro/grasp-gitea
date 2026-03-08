FROM golang:1.24-alpine AS build
ARG BUILD_TAGS=""
WORKDIR /src
COPY . .
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "${BUILD_TAGS}" -o /out/grasp-bridge ./cmd/grasp-bridge
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/grasp-pre-receive ./cmd/grasp-pre-receive

FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite-libs
WORKDIR /app
COPY --from=build /out/grasp-bridge /usr/local/bin/grasp-bridge
COPY --from=build /out/grasp-pre-receive /usr/local/bin/grasp-pre-receive
ENTRYPOINT ["grasp-bridge"]
