package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wispurr/wisp"
)

func main() {
	fConfig := flag.String("config", "", "config to load (file or json string)")
	fPort := flag.Int("port", 0, "port to run on")
	fAllowLoopbackIPs := flag.Bool("allow-loopback", false, "allow loopback IP targets")
	flag.Parse()
	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	var cfg wisp.Config
	var err error

	if *fConfig != "" {
		cfg, err = wisp.LoadConfig(*fConfig)
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			return
		}
	} else {
		cfg = wisp.DefaultConfig()
	}

	if *fPort != 0 {
		cfg.Port = *fPort
	}
	if setFlags["allow-loopback"] {
		cfg.AllowLoopbackIPs = *fAllowLoopbackIPs
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Invalid configuration: %v\n", err)
		os.Exit(2)
	}

	wispConfig := wisp.CreateWispConfig(&cfg)

	wispHandler, err := wisp.NewWispHandler(wispConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to initialize wispurr: %v\n", err)
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(wispConfig.Stats())
	})
	if cfg.StaticDir != "" {
		mux.Handle("/", http.FileServer(http.Dir(cfg.StaticDir)))
		mux.HandleFunc("/wisp", wispHandler)
	} else {
		mux.HandleFunc("/", wispHandler)
	}
	fmt.Printf("[INFO] Starting wispurr on port %d. . .\n", cfg.Port)
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigch
		fmt.Printf("[INFO] Shutting down (signal: %s)\n", sig.String())
		wispConfig.Shutdown()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
			fmt.Printf("[INFO] Shutdown error: %v\n", shutdownErr)
		}
	}()

	err = server.ListenAndServe()
	wispConfig.Shutdown()
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("[INFO] Failed to start wispurr: %v", err)
	}
}
