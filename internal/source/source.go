package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/model"
)

type File struct {
	Ref  string
	Path string
	Raw  []byte
}

var ignoredDirectories = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, ".tmp": {}, "bin": {}, "dist": {}, "node_modules": {}, "vendor": {},
}

func ParseSpecs(values []string) ([]model.Source, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one --source alias=path is required")
	}
	seen := map[string]struct{}{}
	result := make([]model.Source, 0, len(values))
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid source %q: expected alias=path", value)
		}
		alias := strings.TrimSpace(parts[0])
		if strings.ContainsAny(alias, `/\\`) {
			return nil, fmt.Errorf("invalid source alias %q", alias)
		}
		if _, exists := seen[alias]; exists {
			return nil, fmt.Errorf("duplicate source alias %q", alias)
		}
		path, err := filepath.Abs(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("resolve source %q: %w", alias, err)
		}
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("stat source %q: %w", alias, err)
		}
		seen[alias] = struct{}{}
		result = append(result, model.Source{Alias: alias, Path: path})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Alias < result[j].Alias })
	return result, nil
}

func ReadFiles(sources []model.Source) ([]File, error) {
	var result []File
	for _, item := range sources {
		info, err := os.Stat(item.Path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if supportedFile(item.Path) {
				raw, err := os.ReadFile(item.Path)
				if err != nil {
					return nil, err
				}
				result = append(result, File{Ref: item.Alias + "/" + filepath.Base(item.Path), Path: item.Path, Raw: raw})
			}
			continue
		}
		err = filepath.WalkDir(item.Path, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != item.Path {
					if _, ignored := ignoredDirectories[entry.Name()]; ignored {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !supportedFile(path) {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(item.Path, path)
			if err != nil {
				return err
			}
			result = append(result, File{Ref: item.Alias + "/" + filepath.ToSlash(rel), Path: path, Raw: raw})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan source %q: %w", item.Alias, err)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Ref < result[j].Ref })
	return result, nil
}

func Fingerprint(goalRaw []byte, files []File) string {
	hash := sha256.New()
	hash.Write([]byte("goal\x00"))
	hash.Write(goalRaw)
	for _, file := range files {
		hash.Write([]byte("\x00" + file.Ref + "\x00"))
		hash.Write(file.Raw)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func supportedFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json", ".go", ".mod", ".xml", ".gradle", ".properties", ".toml", ".txt",
		".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".conf", ".java", ".kt", ".py", ".lua", ".js", ".ts", ".rb":
		return true
	default:
		return false
	}
}
