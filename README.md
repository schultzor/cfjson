# Load S3 logs into local clickhouse

```shell
docker-compose up -d
cd ./path/to/cloudflare/logs/
gzcat *.log.gz | cfjson -ch
```