# docker run -v /etc/edge-guard:/etc/edge-guard:ro -v edge-guard:/var/lib/edge-guard \
#   --env-file /etc/edge-guard/env --network host ghcr.io/axgrid/edge-guard
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /edge-guard ./cmd/edge-guard

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -S -H -u 10001 edge-guard && install -d -o edge-guard /var/lib/edge-guard
COPY --from=build /edge-guard /usr/local/bin/edge-guard
USER edge-guard
VOLUME /var/lib/edge-guard
ENV STATE_DIRECTORY=/var/lib/edge-guard
ENTRYPOINT ["/usr/local/bin/edge-guard"]
CMD ["-config", "/etc/edge-guard/config.yaml"]
