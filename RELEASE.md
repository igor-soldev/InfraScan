# InfraScan Release Guide

This guide explains how to build and publish the unified InfraScan Docker image to Docker Hub.

## 🚀 Building and Pushing to Docker Hub

The unified image `soldevelo/infrascan` contains both the Web App and the CLI.

### 1. Login to Docker Hub
Ensure you have the necessary permissions for the `soldevelo` organization.

```bash
docker login
```

### 2. Build the Unified Image
Build the image from the root of the repository:

```bash
# Replace <version> with the actual version (e.g., v1.0.3)
docker build -t soldevelo/infrascan:latest -t soldevelo/infrascan:<version> .
```

### 3. Push to Docker Hub
Push both the `latest` tag and the specific version tag:

```bash
docker push soldevelo/infrascan:latest
docker push soldevelo/infrascan:<version>
```

---

## 🛠️ Local Verification before Release

### Test Web Mode
```bash
docker run -d -p 5000:5000 --name infrascan-test soldevelo/infrascan:latest
# Verify by visiting http://localhost:5000
docker stop infrascan-test && docker rm infrascan-test
```

### Test CLI Mode
```bash
docker run --rm -v $(pwd):/scan soldevelo/infrascan:latest --scanner regex
```
