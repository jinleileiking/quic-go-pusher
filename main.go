package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var log = logging.MustGetLogger("example")

var serverInfo = flag.String("s", "localhost:6666", "quic server host and port")
var bitrate = flag.Int("bitrate", 1000000, "send bitrate bps, this will sleep with 10ms")
var message = flag.String("m", "hello gquic from client", "[client] send content")
var isRandom = flag.Bool("r", false, "[client] use random string, works with rlen")
var dump = flag.Bool("d", false, "dump content?")
var auth = flag.Bool("auth", false, "use mutual auth?")
var con = flag.Int("con", 1, "concurrent clients initiated sessions")
var promPort = flag.Int("port", 8811, "prometheus export port")

func main() {
	initLog()
	flag.Parse()

	col := pushCollect{
		Sendbytes: prometheus.NewDesc(
			"quic_pusher_send_bytes",
			"the total bytes send by the client",
			[]string{"connection"},
			nil,
		),
		SendPeriodCostTimeMs: prometheus.NewDesc(
			"quic_pusher_period_send_cost_ms",
			"the cost ms for send burst",
			nil,
			nil,
		),
	}
	prometheus.MustRegister(&col)

	server := http.NewServeMux()
	server.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *promPort), server)

	var wg sync.WaitGroup
	for i := 0; i < *con; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := client(*serverInfo)
			if err != nil {
				panic(err)
			}
			log.Info("Goroutine Done")
		}()
	}
	wg.Wait()

	log.Info("Exited")
}

var quicBytes sync.Map
var sendPeriodCostTimeMs int

func client(serverInfo string) error {

	pool := x509.NewCertPool()
	caCertPath := "ca.crt"

	caCrt, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return errors.Wrap(err, "ReadFile failed")
	}
	pool.AppendCertsFromPEM(caCrt)

	log.Info("Dialing....")

	session, err := quic.DialAddr(serverInfo, &tls.Config{RootCAs: pool, InsecureSkipVerify: !*auth}, &quic.Config{IdleTimeout: 50 * time.Minute})
	if err != nil {
		return err
	}
	defer func() {
		log.Info("Session closed...")
		session.Close()
	}()

	log.Info("Dial Ok")

	stream, err := session.OpenStreamSync()
	if err != nil {
		return errors.Wrap(err, "OpenStreamSync failed")
	}

	log.Infof("OpenStreamSync, stream id :%d", stream.StreamID())

	defer func() {
		log.Info("Stream closed...")
		stream.Close()
	}()

	log.Info("OpenStreamSync done...")

	msg := *message

	loop := 0
	for {

		if *isRandom {
			// msg = RandStringRunes(*bitrate / 8 / 100)
			msg = RandStringRunes(*bitrate / 8)
		}

		if *dump {
			log.Infof("Client %s: Snd '%s', count : %d\n", session.LocalAddr(), msg, loop)
		} else {
			log.Infof("Client %s: Snd count : %d\n", session.LocalAddr(), loop)
		}

		startTime := time.Now()
		var writeBytes int
		writeBytes, err = stream.Write([]byte(msg))
		if err != nil {
			return errors.Wrap(err, "stream.Write failed")
		}
		elapsed := time.Since(startTime)
		sendPeriodCostTimeMs = int(elapsed.Nanoseconds() / 1000)

		log.Info("Done, bytes:", writeBytes)

		bytesSend, _ := quicBytes.Load(session.LocalAddr().String())

		if bytesSend == nil {
			bytesSend = 0
		}

		quicBytes.Store(session.LocalAddr().String(), writeBytes+bytesSend.(int))

		// log.Infof("Cost: %s\n", elapsed)

		// time.Sleep(time.Duration(10 * time.Millisecond))
		loop++
	}

	return nil
}

func getFile(file string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrap(err, "ioutil.ReadFile failed")
	}
	return bytes, nil
}

func getTLSConfig() (tls.Config, error) {

	tlsCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return tls.Config{}, errors.Wrap(err, "LoadX509KeyPair failed")
	}

	return tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

func initLog() {

	var format = logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{color:reset} %{message}`,
	)

	backend := logging.NewLogBackend(os.Stdout, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backendFormatter)
	backendLeveled.SetLevel(logging.ERROR, "")

	logging.SetBackend(backendLeveled)
}

func init() {
	mrand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}

type pushCollect struct {
	Sendbytes            *prometheus.Desc
	SendPeriodCostTimeMs *prometheus.Desc
}

func (c *pushCollect) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Sendbytes
	ch <- c.SendPeriodCostTimeMs
}

func (c *pushCollect) Collect(ch chan<- prometheus.Metric) {

	f := func(k, v interface{}) bool {
		ch <- prometheus.MustNewConstMetric(
			c.Sendbytes,
			prometheus.GaugeValue,
			float64(v.(int)),
			k.(string),
		)
		return true
	}
	quicBytes.Range(f)

	ch <- prometheus.MustNewConstMetric(
		c.SendPeriodCostTimeMs,
		prometheus.GaugeValue,
		float64(sendPeriodCostTimeMs),
	)
}
