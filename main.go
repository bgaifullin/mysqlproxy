package main

import (
	"flag"
)

func main() {
	config := NewConfig()
	flag.StringVar(&config.ListenAddress, "l", config.ListenAddress, "listen address")
	flag.StringVar(&config.MySQLHost, "s", config.MySQLHost, "mysql host")
	flag.StringVar(&config.MySQLUser, "u", config.MySQLUser, "mysql user")
	flag.StringVar(&config.MySQLPassword, "p", config.MySQLPassword, "mysql password")

	flag.Parse()
	StartProxy(config)
}
