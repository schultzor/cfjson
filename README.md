# Load S3 logs into local clickhouse

```shell
go install .
docker-compose up -d
cd ./path/to/cloudflare/logs/
gzcat *.log.gz | cfjson -ch
# or if you've got uncompressed logs already:
cat *.log |cfjson -ch
```
