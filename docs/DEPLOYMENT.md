# Deployment Guide

## Docker (Recommended)

```bash
docker-compose up -d
```

Access at `http://localhost:5001`

### Volumes
- `./uploads:/app/uploads` - Upload directory
- `./output:/app/output` - Results directory
- `./OwnedAssets.txt:/app/OwnedAssets.txt:ro` - Owned assets
- `./config.yaml:/app/config.yaml:ro` - Configuration

## Manual Deployment

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python web_gui.py
```

## Production Considerations

1. **Reverse Proxy**: Use nginx/Apache in front of Flask
2. **WSGI Server**: Use gunicorn instead of Flask dev server
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5001 web_gui:app
   ```
3. **Debug Mode**: Set `debug=False` in production
4. **Secrets**: Secure any API keys in environment variables

## Health Check

```bash
./health_check.sh
# or
curl http://localhost:5001/api/scan/status
```
