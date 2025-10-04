package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type BackupManager struct {
	backupDir     string
	retentionDays int
}

func NewBackupManager(backupDir string, retentionDays int) *BackupManager {
	if backupDir == "" {
		backupDir = "./backups"
	}
	os.MkdirAll(backupDir, 0755)
	return &BackupManager{backupDir: backupDir, retentionDays: retentionDays}
}

func (bm *BackupManager) HandleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	backupType := r.URL.Query().Get("type")
	if backupType == "" {
		http.Error(w, "Parâmetro 'type' é obrigatório", http.StatusBadRequest)
		return
	}

	if err := bm.RestoreLatest(backupType); err != nil {
		http.Error(w, "Erro ao restaurar backup: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Backup de %s restaurado com sucesso", backupType),
	})
}

func (bm *BackupManager) StartScheduler(ctx context.Context) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	bm.Create()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bm.Create()
			bm.Cleanup()
		}
	}
}

func (bm *BackupManager) Create() {
	files := []string{
		"interfaces.json",
		"peers.json",
		"configs/config.json",
		"configs/alert_rules.json",
		"configs/whitelist.json",
	}

	for _, file := range files {
		if err := bm.backupFile(file); err != nil {
			log.Printf("ERRO no backup de %s: %v", file, err)
		}
	}
}

func (bm *BackupManager) backupFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("falha ao ler %s: %w", filename, err)
	}

	backupPath := filepath.Join(bm.backupDir,
		fmt.Sprintf("%s.%s.backup", filepath.Base(filename), time.Now().Format("20060102_150405")))

	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("falha ao escrever backup %s: %w", backupPath, err)
	}
	return nil
}

func (bm *BackupManager) Cleanup() {
	files, err := os.ReadDir(bm.backupDir)
	if err != nil {
		log.Printf("ERRO ao listar backups: %v", err)
		return
	}

	cutoff := time.Now().AddDate(0, 0, -bm.retentionDays)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(bm.backupDir, file.Name())
			if err := os.Remove(path); err != nil {
				log.Printf("ERRO ao remover backup antigo %s: %v", path, err)
			} else {
				log.Printf("Backup antigo removido: %s", path)
			}
		}
	}
}

func (bm *BackupManager) RestoreLatest(backupType string) error {
	files, err := os.ReadDir(bm.backupDir)
	if err != nil {
		return err
	}

	var latest string
	var latestTime time.Time

	for _, file := range files {
		if file.IsDir() || !bm.isBackupFile(file.Name(), backupType) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(latestTime) {
			latestTime = info.ModTime()
			latest = file.Name()
		}
	}

	if latest == "" {
		return fmt.Errorf("nenhum backup encontrado para %s", backupType)
	}

	data, err := os.ReadFile(filepath.Join(bm.backupDir, latest))
	if err != nil {
		return fmt.Errorf("falha ao ler backup: %w", err)
	}

	target := backupTargetPath(backupType)
	if target == "" {
		return fmt.Errorf("tipo de backup desconhecido: %s", backupType)
	}

	if err := os.WriteFile(target, data, 0644); err != nil {
		return fmt.Errorf("falha ao restaurar backup: %w", err)
	}
	log.Printf("Backup restaurado: %s -> %s", latest, target)
	return nil
}

func (bm *BackupManager) isBackupFile(filename, backupType string) bool {
	pattern := fmt.Sprintf("%s.*.backup", backupType)
	matched, _ := filepath.Match(pattern, filename)
	return matched
}

func backupTargetPath(backupType string) string {
	switch backupType {
	case "interfaces.json":
		return "interfaces.json"
	case "config.json":
		return "configs/config.json"
	case "alert_rules.json":
		return "configs/alert_rules.json"
	case "whitelist.json":
		return "configs/whitelist.json"
	default:
		return ""
	}
}
