// Read newline-delimited cloudlfare json log entries from stdin, filter them according to flags
// then write the results back to stdout as json or csv lines. Uses multiple goroutines to handle
// decoding entries, so output ordering will differ from the input unless '-decoders 1' is set.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type clickhouseWriter struct {
	tableName string
	batch     driver.Batch
	conn      clickhouse.Conn
	batchSize int
}

func newClickhouseWriter(ctx context.Context, addr string, auth clickhouse.Auth, tableName string, batchSize int) (*clickhouseWriter, error) {
	dialCount := 0
	// TODO: pass all the host/port/db/user values via params here from argv
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: auth,
		DialContext: func(ctx context.Context, addr string) (net.Conn, error) {
			dialCount++
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		Debug: false, // TODO: set from param
		Debugf: func(format string, v ...any) {
			log.Printf(format, v)
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
				{Name: "cfjson", Version: "0.1"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Exec(ctx, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s
( %s )
Engine = MergeTree
PRIMARY KEY RayID
`,
		tableName,
		(&cfLog{}).ClickHouseSchema())); err != nil {
		return nil, err
	}
	return &clickhouseWriter{
		tableName: tableName,
		conn:      conn,
		batchSize: batchSize,
	}, nil
}

func (w *clickhouseWriter) createBatch(ctx context.Context) error {
	if w.batch == nil {
		b, err := w.conn.PrepareBatch(ctx, fmt.Sprintf("INSERT INTO %s", w.tableName))
		if err != nil {
			return fmt.Errorf("error creating batch: %w", err)
		}
		w.batch = b
	}
	return nil
}

func (w *clickhouseWriter) Write(ctx context.Context, e *cfLog) error {
	if err := w.createBatch(ctx); err != nil {
		return err
	}
	if err := w.batch.Append(e.Row()...); err != nil {
		return err
	}
	if w.batch.Rows() >= w.batchSize {
		if err := w.batch.Send(); err != nil {
			return err
		}
		w.batch = nil
	}
	return nil
}

func (w *clickhouseWriter) Flush() error {
	if w.batch != nil {
		return w.batch.Send()
	}
	return nil
}

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
