FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o wispurr main.go

FROM alpine:3.19

RUN apk --no-cache add ca-certificates && addgroup -S wispurr && adduser -S wispurr -G wispurr

WORKDIR /app

COPY --from=builder /app/wispurr .

USER wispurr

EXPOSE 6001

CMD ["./wispurr", "-config", "config.json"]
