// Read newline-delimited cloudlfare json log entries from stdin, filter them according to flags
// then write the results back to stdout as json or csv lines. Uses multiple goroutines to handle
// decoding entries, so output ordering will differ from the input unless '-decoders 1' is set.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/manifoldco/promptui"
	"github.com/schollz/progressbar/v3"
)

func (c *cfLog) ClickHouseSchema() string {
	results := []string{}
	cType := reflect.TypeOf(*c)
	for i := 0; i < cType.NumField(); i++ {
		field := cType.Field(i)
		if !field.Anonymous {
			if field.PkgPath == "" {
				typeString := ""
				fieldKind := field.Type.Kind()
				if field.Type.Kind() == reflect.Map {
					continue
				}
				if field.Type.Kind() == reflect.Slice {
					fieldKind = field.Type.Elem().Kind()
				}
				switch fieldKind {
				case reflect.String:
					typeString = "String"
					break
				case reflect.Float32:
					typeString = "Float32"
					break
				case reflect.Float64:
					typeString = "Float64"
					break
				case reflect.Int64:
					typeString = "Int64"
					break
				case reflect.Int:
					typeString = "Int32"
					break
				case reflect.Bool:
					typeString = "Boolean"
					break
				case reflect.Interface:
					typeString = "JSON"
					break
				default:
					results = append(results, fmt.Sprintf("%s String", field.Name))
				}
				if field.Type.Kind() == reflect.Slice {
					typeString = fmt.Sprintf("Array(%s)", typeString)
				}
				if field.Type.Kind() == reflect.Map {
					typeString = fmt.Sprintf("Map(String,%s)", typeString)
				}
				results = append(results, fmt.Sprintf("%s %s", field.Name, typeString))
			}
		}
	}
	return strings.Join(results, " , ")
}

func (c *cfLog) Row() []any {
	results := []any{}
	cType := reflect.TypeOf(*c)
	for i := 0; i < cType.NumField(); i++ {
		field := cType.Field(i)
		if !field.Anonymous {
			if field.PkgPath == "" {
				fieldKind := field.Type.Kind()
				if field.Type.Kind() == reflect.Map {
					continue
				}
				switch fieldKind {
				case reflect.String:
					results = append(results, reflect.ValueOf(*c).Field(i).String())
					break
				case reflect.Float32:
					results = append(results, float32(reflect.ValueOf(*c).Field(i).Float()))
					break
				case reflect.Float64:
					results = append(results, reflect.ValueOf(*c).Field(i).Float())
					break
				case reflect.Int64:
					results = append(results, reflect.ValueOf(*c).Field(i).Int())
					break
				case reflect.Int:
					results = append(results, int32(reflect.ValueOf(*c).Field(i).Int()))
					break
				case reflect.Bool:
					results = append(results, reflect.ValueOf(*c).Field(i).Bool())
					break
				case reflect.Slice:
					results = append(results, reflect.ValueOf(*c).Field(i).Interface())
					break
				case reflect.Interface:
					data, err := json.Marshal(reflect.ValueOf(*c).Field(i).Interface())
					if err != nil {
						log.Printf("failed marshaling interface: %s", err.Error())
					}
					results = append(results, string(data))
					break
				default:
					log.Fatalf("unsupported %s", fieldKind)
				}
			}
		}
	}
	return results
}

func loadClickhouse(foldersWithUnzippedS3Logs []string) {
	ctx := context.Background()
	dialCount := 0
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"127.0.0.1:9000"},
		Auth: clickhouse.Auth{
			Database: "default",
			Username: "default",
			Password: "",
		},
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			dialCount++
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		Debug: true,
		Debugf: func(format string, v ...any) {
			fmt.Printf(format, v)
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:          time.Second * 30,
		MaxOpenConns:         5,
		MaxIdleConns:         5,
		ConnMaxLifetime:      time.Duration(10) * time.Minute,
		ConnOpenStrategy:     clickhouse.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 10240,
		ClientInfo: clickhouse.ClientInfo{ // optional, please see Client info section in the README.md
			Products: []struct {
				Name    string
				Version string
			}{
				{Name: "my-app", Version: "0.1"},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, folder := range foldersWithUnzippedS3Logs {
		tableName := filepath.Base(folder)
		if tableName == "" {
			prompt := promptui.Prompt{
				Label: fmt.Sprintf("Please enter a table name for s3 data at path: %s", folder),
			}

			result, err := prompt.Run()
			if err != nil {
				log.Fatal(err)
			}
			tableName = result
		}
		// This is only if you want to drop the tables before adding them
		// if err := conn.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", tableName)); err != nil {
		// 	log.Fatal(err)
		// }
		err = conn.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			%s
		) Engine = MergeTree
		PRIMARY KEY RayID
	`, tableName, (&cfLog{}).ClickHouseSchema()))
		if err != nil {
			log.Fatal(err)
		}
		loadFolder(ctx, conn, folder)
	}
}

func loadFolder(ctx context.Context, conn clickhouse.Conn, dirName string) {
	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf("INSERT INTO %s", dirName))
	if err != nil {
		log.Fatal(err)
	}
	dirs, err := os.ReadDir(dirName)
	if err != nil {
		log.Fatal(err)
	}
	bar := progressbar.Default(int64(len(dirs)))
	for _, dir := range dirs {
		bar.Add(1)
		if !dir.IsDir() && strings.HasSuffix(dir.Name(), ".log") {
			f, err := os.Open(path.Join(dirName, dir.Name()))
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			s := bufio.NewScanner(f)
			for s.Scan() {
				line := s.Text()
				logLine := cfLog{}
				err = json.Unmarshal([]byte(line), &logLine)
				if err != nil {
					log.Fatal(err)
				}
				err = batch.Append(logLine.Row()...)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
	bar.Finish()
	err = batch.Send()
	if err != nil {
		log.Fatal(err)
	}
}
