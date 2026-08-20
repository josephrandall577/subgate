# 编译与运行都在容器内完成,主机无需 Go 工具链
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /subgate .

FROM alpine:3.22
# tzdata: /etc/localtime 挂载缺失时 TZ 环境变量仍可生效，避免 24h 统计图退化到 UTC
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /subgate /usr/local/bin/subgate
ENTRYPOINT ["subgate"]
CMD ["-data", "/data"]
