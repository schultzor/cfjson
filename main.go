// Read newline-delimited cloudlfare json log entries from stdin, filter them according to flags
// then write the results back to stdout as json or csv lines. Uses multiple goroutines to handle
// decoding entries, so output ordering will differ from the input unless '-decoders 1' is set.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"golang.org/x/sync/errgroup"
)

const nanosPerSec = 1_000_000_000

type filter func(*cfLog) bool

var (
	fieldmap     map[string]int
	fieldnames   []string
	fieldindexes []int
	filters      []filter
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	if i == nil {
		return ""
	}
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// see https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/
type cfLog struct {
	CacheCacheStatus                      string
	CacheResponseBytes                    int
	CacheResponseStatus                   int
	CacheTieredFill                       bool
	ClientASN                             int
	ClientCountry                         string
	ClientDeviceType                      string
	ClientIP                              string
	ClientIPClass                         string
	ClientMTLSAuthCertFingerprint         string
	ClientMTLSAuthStatus                  string
	ClientRequestBytes                    int
	ClientRequestHost                     string
	ClientRequestMethod                   string
	ClientRequestPath                     string
	ClientRequestProtocol                 string
	ClientRequestReferer                  string
	ClientRequestScheme                   string
	ClientRequestSource                   string
	ClientRequestURI                      string
	ClientRequestUserAgent                string
	ClientSSLCipher                       string
	ClientSSLProtocol                     string
	ClientTCPRTTMs                        int
	ClientXRequestedWith                  string
	EdgeCFConnectingO2O                   bool
	EdgeColoCode                          string
	EdgeColoID                            int
	EdgeEndTimestamp                      int64
	EdgePathingOp                         string
	EdgePathingSrc                        string
	EdgePathingStatus                     string
	EdgeRateLimitAction                   string
	EdgeRateLimitID                       int
	EdgeRequestHost                       string
	EdgeResponseBodyBytes                 int
	EdgeResponseBytes                     int
	EdgeResponseCompressionRatio          float32
	EdgeResponseContentType               string
	EdgeResponseStatus                    int
	EdgeServerIP                          string
	EdgeStartTimestamp                    int64
	EdgeTimeToFirstByteMs                 int
	FirewallMatchesActions                []string
	FirewallMatchesRuleIDs                string
	FirewallMatchesSources                string
	OriginDNSResponseTimeMs               int
	OriginIP                              string
	OriginRequestHeaderSendDurationMs     int
	OriginResponseBytes                   int
	OriginResponseDurationMs              int
	OriginResponseHTTPExpires             string
	OriginResponseHTTPLastModified        string
	OriginResponseHeaderReceiveDurationMs int
	OriginResponseStatus                  int
	OriginResponseTime                    int64
	OriginSSLProtocol                     string
	OriginTCPHandshakeDurationMs          int
	OriginTLSHandshakeDurationMs          int
	ParentRayID                           string
	RayID                                 string
	RequestHeaders                        map[string]any
	ResponseHeaders                       map[string]any
	SecurityLevel                         string
	SmartRouteColoID                      int
	UpperTierColoID                       int
	WAFAction                             string
	WAFFlags                              string
	WAFMatchedVar                         string
	WAFProfile                            string
	WAFRuleID                             string
	WAFRuleMessage                        string
	WorkerCPUTime                         int64
	WorkerStatus                          string
	WorkerSubrequest                      bool
	WorkerSubrequestCount                 int
	WorkerWallTimeUs                      int
	ZoneID                                int
	ZoneName                              string

	// non-exported/internal fields
	src *string // string entry was parsed from
}

func (e *cfLog) parse(js string) error {
	if err := json.Unmarshal([]byte(js), e); err != nil {
		return fmt.Errorf("error decoding log %q: %w", js, err)
	}
	e.src = &js
	return nil
}

func (e cfLog) toCsv() []string {
	var ret []string
	sv := reflect.ValueOf(e)
	for _, idx := range fieldindexes {
		fv := sv.Field(idx)
		ret = append(ret, fmt.Sprint(fv.Interface()))
	}
	return ret
}

func init() {
	fieldmap = make(map[string]int)
	var tmp cfLog
	st := reflect.TypeOf(tmp)
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if f.IsExported() {
			fieldindexes = append(fieldindexes, i)
			fieldnames = append(fieldnames, f.Name)
			fieldmap[f.Name] = i
		}
	}
}

type tstamp int64

func (v tstamp) String() string {
	if v > 0 {
		return time.Unix(int64(v)/nanosPerSec, int64(v)%nanosPerSec).UTC().Format(time.RFC3339)
	}
	return ""
}
func (v *tstamp) Set(s string) error {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	*v = tstamp(ts.UnixNano())
	return nil
}

func checkFilters(entry *cfLog) bool {
	for _, f := range filters {
		if !f(entry) {
			return false
		}
	}
	return true
}

func decode(input <-chan string, output chan<- *cfLog) error {
	for m := range input {
		var entry cfLog
		if err := entry.parse(m); err != nil {
			return err
		}
		if !checkFilters(&entry) {
			continue
		}
		output <- &entry
	}
	return nil
}

// using reflection to grab struct field values at runtime is slow
// but we're running parallel decoders so maybe the runtime penalty is ok
// in exchange for cutting down the amount of flag-processing code?

func getStringFilter(fieldName string) func(string) error {
	return func(argValue string) error {
		// TODO: parse value string for things like "!", "~", etc, handle lists of values?
		idx, ok := fieldmap[fieldName]
		if !ok {
			return fmt.Errorf("no log field named %q available", fieldName)
		}

		filters = append(filters, func(l *cfLog) bool {
			v := reflect.ValueOf(*l).Field(idx).String()
			return v == argValue
		})
		return nil
	}
}

func getIntFilter(fieldName string) func(string) error {
	return func(argValue string) error {
		// TODO: parse value string for things like "!", "~", "<", ">", etc
		idx, ok := fieldmap[fieldName]
		if !ok {
			return fmt.Errorf("no log field named %q available", fieldName)
		}
		argInt, err := strconv.ParseInt(argValue, 10, 0)
		if err != nil {
			return fmt.Errorf("error parsing %q to int: %w", argValue, err)
		}

		filters = append(filters, func(l *cfLog) bool {
			v := reflect.ValueOf(*l).Field(idx).Int()
			return v == argInt
		})
		return nil
	}
}

type emitter func(e *cfLog) error

type logReader interface {
	readAll(io.Reader, chan<- *cfLog) (int64, error)
}

type jsonReader struct {
	decoderCount int
}

func (j *jsonReader) readAll(input io.Reader, output chan<- *cfLog) (int64, error) {
	var group errgroup.Group
	var count int64
	log.Printf("running %d json decoders", j.decoderCount)
	lines := make(chan string, 100)
	for i := 0; i < j.decoderCount; i++ {
		group.Go(func() error {
			return decode(lines, output)
		})
	}
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		lines <- scanner.Text()
		count++
	}
	close(lines)
	if err := scanner.Err(); err != nil {
		return count, err
	}
	return count, group.Wait()
}

type gobReader struct{}

func (g *gobReader) readAll(input io.Reader, output chan<- *cfLog) (int64, error) {
	var count int64
	decoder := gob.NewDecoder(input)
	for {
		var entry cfLog
		err := decoder.Decode(&entry)
		if err == io.EOF {
			break
		} else if err != nil {
			return count, err
		}
		count++
		output <- &entry
	}
	return count, nil
}

func main() {
	procStart := time.Now().UTC()
	log.SetPrefix("cfjson:")
	log.SetFlags(0)
	var start, end tstamp
	flag.Var(&start, "start", "optional time range start, e.g. "+procStart.Add(-1*time.Hour).Format(time.RFC3339))
	flag.Var(&end, "end", "optional time range end, e.g. "+procStart.Format(time.RFC3339))
	gobIn := flag.Bool("b", false, "read gob binary input instead of json")
	gobOut := flag.Bool("gob", false, "emit gob binary output instead of json")
	csvOut := flag.Bool("csv", false, "emit csv output instead of json")

	chOut := flag.Bool("ch", false, "load data into local clickhouse instance")
	chBatchSize := flag.Int("chbatch", 1000, "clickhouse insert batch size")
	chTableName := flag.String("chtable", "cloudflare", "clickhouse table name to insert logs into")

	chHost := flag.String("chhost", "127.0.0.1", "clickhouse host")
	chPort := flag.Int("chport", 9000, "clickhouse port")

	chDatabase := flag.String("chdatabase", "default", "clickhouse database")
	chUsername := flag.String("chuser", "default", "clickhouse username")
	chPassword := flag.String("chpassword", "", "clickhouse password")

	decoders := flag.Int("decoders", max(1, runtime.NumCPU()/2), "number of decoder goroutines to run")
	flag.Func("colo", "match on EdgeColoCode field", getStringFilter("EdgeColoCode"))
	flag.Func("contenttype", "match on EdgeResponseContentType field", getStringFilter("EdgeResponseContentType"))
	flag.Func("pathingstatus", "match on EdgePathingStatus", getStringFilter("EdgePathingStatus"))
	flag.Func("status", "match on EdgeResponseStatus", getIntFilter("EdgeResponseStatus"))
	flag.Func("originstatus", "match on OriginResponseStatus", getIntFilter("OriginResponseStatus"))
	flag.Func("method", "match on ClientRequestMethod", getStringFilter("ClientRequestMethod"))
	flag.Func("path", "match on ClientRequestPath", getStringFilter("ClientRequestPath"))
	flag.Func("source", "match on ClientRequestSource", getStringFilter("ClientRequestSource"))
	flag.Func("host", "match on ClientRequestHost", getStringFilter("ClientRequestHost"))
	flag.Func("ray", "match on RayID", getStringFilter("RayID"))
	flag.Func("parentray", "match on ParentRayID", getStringFilter("ParentRayID"))
	flag.Func("cachestatus", "match on CacheCacheStatus", getStringFilter("CacheCacheStatus"))
	flag.Parse()

	if start != 0 {
		filters = append(filters, func(l *cfLog) bool {
			return l.EdgeStartTimestamp >= int64(start)
		})
	}
	if end != 0 {
		filters = append(filters, func(l *cfLog) bool {
			return l.EdgeStartTimestamp <= int64(end)
		})
	}
	ctx := context.Background()

	// pick output writer type
	var emit emitter
	switch {
	case *chOut:
		chAuth := clickhouse.Auth{
			Database: *chDatabase,
			Username: *chUsername,
			Password: *chPassword,
		}
		chw, err := newClickhouseWriter(ctx, fmt.Sprintf("%s:%d", *chHost, *chPort), chAuth, *chTableName, *chBatchSize)
		if err != nil {
			log.Fatalf("error creating clickhouse writer: %w", err)
		}
		defer chw.Flush()
		emit = func(e *cfLog) error {
			err := chw.Write(ctx, e)
			if err != nil {
				log.Fatal("ch error:", err)
			}
			return err
		}
	case *csvOut:
		csvWriter := csv.NewWriter(os.Stdout)
		csvWriter.Write(fieldnames)
		defer csvWriter.Flush()
		emit = func(e *cfLog) error {
			return csvWriter.Write(e.toCsv())
		}
	case *gobOut:
		gobOut := gob.NewEncoder(os.Stdout)
		emit = func(e *cfLog) error {
			return gobOut.Encode(*e)
		}
	default:
		emit = func(e *cfLog) error {
			if e.src != nil {
				fmt.Println(*e.src)
			} else {
				fmt.Println(e)
			}
			return nil
		}
	}
	logEntries := make(chan *cfLog, 100)
	var writerGroup errgroup.Group
	writerGroup.Go(func() error {
		for e := range logEntries {
			emit(e)
		}
		return nil
	})

	// pick input type
	var reader logReader
	if *gobIn {
		reader = &gobReader{}
	} else {
		reader = &jsonReader{*decoders}
	}
	count, err := reader.readAll(os.Stdin, logEntries)
	if err != nil {
		log.Fatalf("error reading input: %v", err)
	}
	close(logEntries)
	writerGroup.Wait()
	log.Printf("read %d entries in %v", count, time.Since(procStart))
}
