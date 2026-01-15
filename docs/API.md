# API Reference

Base URL: `http://localhost:5001`

## Endpoints

### GET /api/results
Returns current scan results as JSON array.

### POST /api/scan
Start a new scan.

**Request Body:**
```json
{
  "csv_file": "filename.csv",
  "status_filter": "all",
  "owned_file": "OwnedAssets.txt"
}
```

**Response:**
```json
{"status": "success", "message": "Scan started"}
```

### GET /api/scan/status
Get scan progress.

**Response:**
```json
{
  "in_progress": true,
  "progress": 50,
  "status": "Processing assets..."
}
```

### POST /api/upload
Upload CSV file (multipart/form-data with `file` field).

### GET /api/files
List uploaded files with size and modification time.

### GET /api/download/\<filename\>
Download result file from output directory.

### GET /load/\<filename\>
Load results from output CSV into memory.
