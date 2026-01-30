package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config holds all configuration from environment variables
type Config struct {
	DocsRepoURL     string // Git repo URL for documentation
	DocsLocalPath   string // Local path to store docs
	OllamaHost      string // Ollama host for embeddings
	OllamaPort      string // Ollama port
	EmbeddingModel  string // Model for embeddings (nomic-embed-text)
	ChromaHost      string // ChromaDB host
	ChromaPort      string // ChromaDB port
	CollectionName  string // ChromaDB collection name
	SyncInterval    int    // Sync interval in hours (0 = once and exit)
	ChunkSize       int    // Max characters per chunk
	ChunkOverlap    int    // Overlap between chunks
}

func loadConfig() *Config {
	return &Config{
		DocsRepoURL:    getEnv("DOCS_REPO_URL", "https://github.com/cubeos-app/docs.git"),
		DocsLocalPath:  getEnv("DOCS_LOCAL_PATH", "/cubeos/docs"),
		OllamaHost:     getEnv("OLLAMA_HOST", "192.168.42.1"),
		OllamaPort:     getEnv("OLLAMA_PORT", "11434"),
		EmbeddingModel: getEnv("EMBEDDING_MODEL", "nomic-embed-text"),
		ChromaHost:     getEnv("CHROMADB_HOST", "192.168.42.1"),
		ChromaPort:     getEnv("CHROMADB_PORT", "8000"),
		CollectionName: getEnv("COLLECTION_NAME", "cubeos_docs"),
		SyncInterval:   getEnvInt("SYNC_INTERVAL_HOURS", 6),
		ChunkSize:      getEnvInt("CHUNK_SIZE", 500),
		ChunkOverlap:   getEnvInt("CHUNK_OVERLAP", 50),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		var i int
		if _, err := fmt.Sscanf(val, "%d", &i); err == nil {
			return i
		}
	}
	return defaultVal
}

// Document represents a chunk of documentation
type Document struct {
	ID       string            `json:"id"`
	Content  string            `json:"content"`
	Metadata map[string]string `json:"metadata"`
}

// ChromaDB API structures (v2)
type ChromaCollection struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ChromaAddRequest struct {
	IDs        []string            `json:"ids"`
	Embeddings [][]float32         `json:"embeddings"`
	Documents  []string            `json:"documents"`
	Metadatas  []map[string]string `json:"metadatas"`
}

type ChromaQueryRequest struct {
	QueryEmbeddings [][]float32 `json:"query_embeddings"`
	NResults        int         `json:"n_results"`
	Include         []string    `json:"include"`
}

type ChromaQueryResponse struct {
	IDs        [][]string            `json:"ids"`
	Documents  [][]string            `json:"documents"`
	Metadatas  [][]map[string]string `json:"metadatas"`
	Distances  [][]float32           `json:"distances"`
}

type OllamaEmbeddingRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type OllamaEmbeddingResponse struct {
	Embedding []float32 `json:"embedding"`
}

func main() {
	config := loadConfig()

	log.Printf("CubeOS Docs Indexer starting...")
	log.Printf("  Docs repo: %s", config.DocsRepoURL)
	log.Printf("  Local path: %s", config.DocsLocalPath)
	log.Printf("  Ollama: %s:%s (model: %s)", config.OllamaHost, config.OllamaPort, config.EmbeddingModel)
	log.Printf("  ChromaDB: %s:%s (collection: %s)", config.ChromaHost, config.ChromaPort, config.CollectionName)
	log.Printf("  Sync interval: %d hours", config.SyncInterval)

	// Run once immediately
	if err := runIndexing(config); err != nil {
		log.Printf("ERROR: Indexing failed: %v", err)
	}

	// If sync interval is 0, exit after one run
	if config.SyncInterval == 0 {
		log.Println("Sync interval is 0, exiting after single run")
		return
	}

	// Schedule periodic runs
	ticker := time.NewTicker(time.Duration(config.SyncInterval) * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Starting scheduled sync...")
		if err := runIndexing(config); err != nil {
			log.Printf("ERROR: Scheduled indexing failed: %v", err)
		}
	}
}

func runIndexing(config *Config) error {
	// Step 1: Sync docs from Git
	log.Println("Step 1: Syncing documentation from Git...")
	if err := syncDocs(config); err != nil {
		return fmt.Errorf("git sync failed: %w", err)
	}

	// Step 2: Find all markdown files
	log.Println("Step 2: Finding markdown files...")
	mdFiles, err := findMarkdownFiles(config.DocsLocalPath)
	if err != nil {
		return fmt.Errorf("failed to find markdown files: %w", err)
	}
	log.Printf("  Found %d markdown files", len(mdFiles))

	if len(mdFiles) == 0 {
		log.Println("No markdown files found, nothing to index")
		return nil
	}

	// Step 3: Parse and chunk documents
	log.Println("Step 3: Parsing and chunking documents...")
	documents, err := parseAndChunkDocuments(mdFiles, config)
	if err != nil {
		return fmt.Errorf("failed to parse documents: %w", err)
	}
	log.Printf("  Created %d chunks", len(documents))

	// Step 4: Ensure collection exists
	log.Println("Step 4: Ensuring ChromaDB collection exists...")
	collectionID, err := ensureCollection(config)
	if err != nil {
		return fmt.Errorf("failed to ensure collection: %w", err)
	}
	log.Printf("  Collection ID: %s", collectionID)

	// Step 5: Generate embeddings and store
	log.Println("Step 5: Generating embeddings and storing in ChromaDB...")
	if err := indexDocuments(documents, collectionID, config); err != nil {
		return fmt.Errorf("failed to index documents: %w", err)
	}

	log.Println("Indexing complete!")
	return nil
}

func syncDocs(config *Config) error {
	// Check if directory exists and is a git repo
	gitDir := filepath.Join(config.DocsLocalPath, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		// Git repo exists, pull updates
		log.Println("  Pulling updates...")
		cmd := exec.Command("git", "-C", config.DocsLocalPath, "pull", "--ff-only")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Pull failed, try reset
			log.Println("  Pull failed, resetting to origin...")
			exec.Command("git", "-C", config.DocsLocalPath, "fetch", "origin").Run()
			exec.Command("git", "-C", config.DocsLocalPath, "reset", "--hard", "origin/main").Run()
		}
	} else {
		// Clone fresh
		log.Printf("  Cloning %s...", config.DocsRepoURL)
		// Remove existing directory if it exists but isn't a git repo
		os.RemoveAll(config.DocsLocalPath)
		cmd := exec.Command("git", "clone", "--depth=1", config.DocsRepoURL, config.DocsLocalPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
	}
	return nil
}

func findMarkdownFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func parseAndChunkDocuments(files []string, config *Config) ([]Document, error) {
	var documents []Document

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("  Warning: Could not read %s: %v", file, err)
			continue
		}

		// Get relative path for metadata
		relPath, _ := filepath.Rel(config.DocsLocalPath, file)
		
		// Extract title from first heading or filename
		title := extractTitle(string(content), filepath.Base(file))

		// Chunk the content
		chunks := chunkText(string(content), config.ChunkSize, config.ChunkOverlap)

		for i, chunk := range chunks {
			// Generate deterministic ID based on content hash
			hash := sha256.Sum256([]byte(file + fmt.Sprintf("%d", i) + chunk))
			id := hex.EncodeToString(hash[:8])

			documents = append(documents, Document{
				ID:      id,
				Content: chunk,
				Metadata: map[string]string{
					"source":    relPath,
					"title":     title,
					"chunk":     fmt.Sprintf("%d", i),
					"total":     fmt.Sprintf("%d", len(chunks)),
				},
			})
		}
	}

	return documents, nil
}

func extractTitle(content, filename string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	// Fall back to filename without extension
	return strings.TrimSuffix(filename, filepath.Ext(filename))
}

func chunkText(text string, chunkSize, overlap int) []string {
	// Clean up the text
	text = strings.ReplaceAll(text, "\r\n", "\n")
	
	// Split by paragraphs first
	paragraphs := strings.Split(text, "\n\n")
	
	var chunks []string
	var currentChunk strings.Builder

	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}

		// If adding this paragraph would exceed chunk size, save current and start new
		if currentChunk.Len()+len(para) > chunkSize && currentChunk.Len() > 0 {
			chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
			
			// Start new chunk with overlap from end of previous
			prevContent := currentChunk.String()
			currentChunk.Reset()
			if len(prevContent) > overlap {
				// Add last 'overlap' characters as context
				currentChunk.WriteString(prevContent[len(prevContent)-overlap:])
				currentChunk.WriteString("\n\n")
			}
		}

		currentChunk.WriteString(para)
		currentChunk.WriteString("\n\n")
	}

	// Don't forget the last chunk
	if currentChunk.Len() > 0 {
		chunks = append(chunks, strings.TrimSpace(currentChunk.String()))
	}

	// If no chunks were created, create one from the whole text
	if len(chunks) == 0 && len(text) > 0 {
		chunks = append(chunks, strings.TrimSpace(text))
	}

	return chunks
}

func ensureCollection(config *Config) (string, error) {
	baseURL := fmt.Sprintf("http://%s:%s/api/v2", config.ChromaHost, config.ChromaPort)
	tenant := "default_tenant"
	database := "default_database"

	// Try to get existing collection
	url := fmt.Sprintf("%s/tenants/%s/databases/%s/collections/%s", baseURL, tenant, database, config.CollectionName)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to check collection: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var collection ChromaCollection
		if err := json.NewDecoder(resp.Body).Decode(&collection); err == nil {
			// Delete existing to start fresh (ensures clean re-index)
			log.Println("  Deleting existing collection for clean re-index...")
			req, _ := http.NewRequest("DELETE", url, nil)
			http.DefaultClient.Do(req)
		}
	}

	// Create new collection
	log.Println("  Creating collection...")
	createURL := fmt.Sprintf("%s/tenants/%s/databases/%s/collections", baseURL, tenant, database)
	createBody := map[string]interface{}{
		"name": config.CollectionName,
	}
	bodyBytes, _ := json.Marshal(createBody)

	resp, err = http.Post(createURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create collection: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create collection: %s", string(body))
	}

	var collection ChromaCollection
	if err := json.NewDecoder(resp.Body).Decode(&collection); err != nil {
		return "", fmt.Errorf("failed to decode collection response: %w", err)
	}

	return collection.ID, nil
}

func indexDocuments(documents []Document, collectionID string, config *Config) error {
	if len(documents) == 0 {
		return nil
	}

	baseURL := fmt.Sprintf("http://%s:%s/api/v2", config.ChromaHost, config.ChromaPort)
	ollamaURL := fmt.Sprintf("http://%s:%s", config.OllamaHost, config.OllamaPort)

	// Process in batches of 10
	batchSize := 10
	for i := 0; i < len(documents); i += batchSize {
		end := i + batchSize
		if end > len(documents) {
			end = len(documents)
		}
		batch := documents[i:end]

		var ids []string
		var embeddings [][]float32
		var contents []string
		var metadatas []map[string]string

		for j, doc := range batch {
			log.Printf("  Embedding document %d/%d: %s (chunk %s)", i+j+1, len(documents), doc.Metadata["source"], doc.Metadata["chunk"])

			// Generate embedding via Ollama
			embedding, err := getEmbedding(ollamaURL, config.EmbeddingModel, doc.Content)
			if err != nil {
				log.Printf("  Warning: Failed to embed document %s: %v", doc.ID, err)
				continue
			}

			ids = append(ids, doc.ID)
			embeddings = append(embeddings, embedding)
			contents = append(contents, doc.Content)
			metadatas = append(metadatas, doc.Metadata)
		}

		if len(ids) == 0 {
			continue
		}

		// Add to ChromaDB
		addURL := fmt.Sprintf("%s/collections/%s/add", baseURL, collectionID)
		addReq := ChromaAddRequest{
			IDs:        ids,
			Embeddings: embeddings,
			Documents:  contents,
			Metadatas:  metadatas,
		}
		bodyBytes, _ := json.Marshal(addReq)

		resp, err := http.Post(addURL, "application/json", bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("failed to add documents to ChromaDB: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("ChromaDB add failed: %s", string(body))
		}

		log.Printf("  Added batch of %d documents", len(ids))
	}

	return nil
}

func getEmbedding(ollamaURL, model, text string) ([]float32, error) {
	reqBody := OllamaEmbeddingRequest{
		Model:  model,
		Prompt: text,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(ollamaURL+"/api/embeddings", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama embedding failed: %s", string(body))
	}

	var embResp OllamaEmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&embResp); err != nil {
		return nil, fmt.Errorf("failed to decode embedding response: %w", err)
	}

	return embResp.Embedding, nil
}
