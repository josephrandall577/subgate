package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	dataDir := flag.String("data", "data", "数据目录（配置+日志）")
	initMode := flag.Bool("init", false, "写入 secrets.json 后退出")
	user := flag.String("user", "admin", "-init: 管理员用户名")
	pass := flag.String("pass", "", "-init: 管理员密码（空则随机生成）")
	panel := flag.String("panel", "", "-init: 后台隐藏路径（空则随机生成）")
	flag.Parse()

	if *initMode {
		sec, err := writeSecrets(*dataDir, *user, *pass, *panel)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("secrets.json 已写入：用户 %s，后台路径 /%s/", sec.User, sec.PanelPath)
		return
	}

	store, err := LoadStore(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	logger, err := NewLogger(filepath.Join(*dataDir, "logs"))
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Close()
	go func() { // 日志自动清理：每小时按配置保留天数删过期文件（改配置热生效，今天永不删）
		for {
			if n, _ := logger.Cleanup(store.Config().LogRetainDays); n > 0 {
				log.Printf("日志自动清理: 删除 %d 个过期文件", n)
			}
			time.Sleep(time.Hour)
		}
	}()
	cloud := NewCloudIPs(filepath.Join(*dataDir, "cloud_ips.json"))
	go cloud.AutoRefresh(store)

	cfg := store.Config()
	if cfg.Upstream == "" {
		log.Printf("警告: 尚未配置上游地址，请到管理后台设置")
	}

	gwSrv := &http.Server{
		Addr: cfg.GatewayAddr, Handler: NewGateway(store, logger, cloud),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 65 * time.Second,
	}
	adSrv := &http.Server{
		Addr: cfg.AdminAddr, Handler: NewAdmin(store, logger, cloud),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("网关监听 %s（订阅路径 %s）", cfg.GatewayAddr, cfg.SubPath)
		if err := gwSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("网关: %v", err)
		}
	}()
	go func() {
		_, panelPath := store.SecretsInfo()
		log.Printf("管理后台监听 %s，路径 /%s/", cfg.AdminAddr, panelPath)
		if err := adSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("管理后台: %v", err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gwSrv.Shutdown(ctx)
	adSrv.Shutdown(ctx)
}
