package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"synapse/internal/output"
)

// Config holds scanner configuration.
type Config struct {
	Concurrency int
	RateLimit   int
	Timeout     time.Duration
	Banner      bool
}

// Scanner orchestrates the scanning process.
type Scanner struct {
	cfg     Config
	limiter *rate.Limiter
	writer  *output.Writer
}

// New creates a new Scanner.
func New(cfg Config, w *output.Writer) *Scanner {
	var limiter *rate.Limiter
	if cfg.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	} else {
		limiter = rate.NewLimiter(rate.Inf, 0)
	}

	return &Scanner{
		cfg:     cfg,
		limiter: limiter,
		writer:  w,
	}
}

// ScanTask represents a single port scan job.
type ScanTask struct {
	IP   string
	Port int
}

// Run executes the scan with the given IPs and ports.
func (s *Scanner) Run(ctx context.Context, ips <-chan string, ports []int) error {
	tasks := make(chan ScanTask, s.cfg.Concurrency*2)
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, tasks)
	}

	// Generate tasks
	go func() {
		defer close(tasks)
		for ip := range ips {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case tasks <- ScanTask{IP: ip, Port: port}:
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan ScanTask) {
	defer wg.Done()

	// Dialer can be reused
	dialer := &net.Dialer{
		Timeout: s.cfg.Timeout,
	}

	for task := range tasks {
		// Respect rate limit
		if err := s.limiter.Wait(ctx); err != nil {
			// Context canceled
			return
		}

		s.scanPort(ctx, dialer, task)
	}
}

func (s *Scanner) scanPort(ctx context.Context, dialer *net.Dialer, task ScanTask) {
	target := fmt.Sprintf("%s:%d", task.IP, task.Port)

	// Context for the specific dial operation, bounded by dialer timeout
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		// Port closed or filtered
		return
	}
	defer conn.Close()

	res := output.Result{
		IP:    task.IP,
		Port:  task.Port,
		State: "OPEN",
	}

	if s.cfg.Banner {
		// Optional banner grabbing
		res.Banner = grabBanner(conn, s.cfg.Timeout)
	}

	// Output result
	if err := s.writer.WriteResult(res); err != nil {
		s.writer.Log("error writing result: %v", err)
	}
}

func grabBanner(conn net.Conn, timeout time.Duration) string {
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		// Could send a simple HTTP request if needed to coax a banner, but standard masscan approach is passive first.
		return ""
	}

	// Clean up unprintable chars
	banner := string(buf[:n])
	banner = cleanBanner(banner)
	return banner
}

func cleanBanner(b string) string {
	var clean []rune
	for _, r := range b {
		if r >= 32 && r <= 126 {
			clean = append(clean, r)
		} else if r == '\r' || r == '\n' {
			// replace newlines with space for single-line output
			clean = append(clean, ' ')
		}
	}
	return string(clean)
}
