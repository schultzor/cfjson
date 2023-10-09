# Load S3 logs into local clickhouse

```shell
docker-compose up -d

go run main.go -clickhouse -folder <path-to-folder-with-unzipped-s3-log-data>
```