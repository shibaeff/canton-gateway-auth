FROM golang:1.26.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/canton-gateway-auth .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/canton-gateway-auth /canton-gateway-auth
USER nonroot:nonroot
EXPOSE 9001 9090
ENTRYPOINT ["/canton-gateway-auth"]
