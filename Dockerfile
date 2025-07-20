FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main .

FROM alpine:latest

WORKDIR /root/

RUN apk --no-cache add ca-certificates
COPY --from=builder /app/main .

EXPOSE 8001

CMD ["./main"] 