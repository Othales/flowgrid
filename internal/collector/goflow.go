package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func StartGoflow(ctx context.Context, netflowPort int) (*exec.Cmd, io.ReadCloser, io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, "goflow2",
		"-listen", fmt.Sprintf("netflow://0.0.0.0:%d", netflowPort),
		"-format", "json", "-addr", "")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("falha ao iniciar goflow2: %w", err)
	}
	log.Printf("Goflow2 na porta %d", netflowPort)
	return cmd, stdout, stderr, nil
}

func LogGoflowErrors(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		log.Printf("[goflow2 stderr] %s", scanner.Text())
	}
}

func WaitForShutdown(cancel context.CancelFunc, server *http.Server, cmd *exec.Cmd) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("Recebido sinal de desligamento...")
	cancel()

	ctx, cancelTimeout := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelTimeout()

	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Erro no shutdown do servidor HTTP: %v", err)
		}
	}

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}
}
