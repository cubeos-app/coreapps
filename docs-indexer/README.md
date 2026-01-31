# CubeOS Docs Indexer

Syncs documentation from a Git repository and indexes it into ChromaDB for RAG (Retrieval Augmented Generation).

## Features

- **Git Sync**: Automatically clones/pulls documentation from configurable Git repo
- **Chunking**: Splits documents into optimal chunks for embedding
- **Embeddings**: Uses Ollama with nomic-embed-text model
- **ChromaDB Storage**: Stores embeddings in ChromaDB v2 API
- **Scheduled Sync**: Runs periodically to keep docs up-to-date
- **Offline Ready**: Works after initial sync even without internet

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCS_REPO_URL` | `https://github.com/cubeos-app/docs.git` | Git repository URL |
| `DOCS_LOCAL_PATH` | `/cubeos/docs` | Local path to store docs |
| `OLLAMA_HOST` | `10.42.24.1` | Ollama server host |
| `OLLAMA_PORT` | `6030` | Ollama server port |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Model for embeddings |
| `CHROMADB_HOST` | `10.42.24.1` | ChromaDB server host |
| `CHROMADB_PORT` | `6031` | ChromaDB server port |
| `COLLECTION_NAME` | `cubeos_docs` | ChromaDB collection name |
| `SYNC_INTERVAL_HOURS` | `6` | Sync interval (0 = run once) |
| `CHUNK_SIZE` | `500` | Max characters per chunk |
| `CHUNK_OVERLAP` | `50` | Overlap between chunks |

## Usage

### As a coreapp (recommended)

```bash
cd /cubeos/coreapps/docs-indexer/appconfig
docker compose up -d
```

### Manual run

```bash
docker run --rm --network host \
  -e DOCS_REPO_URL=https://github.com/cubeos-app/docs.git \
  -e SYNC_INTERVAL_HOURS=0 \
  -v /cubeos/docs:/cubeos/docs \
  ghcr.io/cubeos-app/docs-indexer:latest
```

## How It Works

1. **Sync**: Clones or pulls the documentation repository
2. **Parse**: Finds all `.md` files recursively
3. **Chunk**: Splits documents into ~500 char chunks with overlap
4. **Embed**: Generates embeddings via Ollama (nomic-embed-text)
5. **Store**: Saves embeddings and metadata to ChromaDB
6. **Repeat**: Waits for sync interval and repeats

## Building

```bash
# Build locally
docker build -t docs-indexer .

# Run
docker run --rm --network host -v /cubeos/docs:/cubeos/docs docs-indexer
```

## License

Apache 2.0
