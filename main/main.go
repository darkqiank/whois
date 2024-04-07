package main

import (
	"flag"
	"fmt"
	"github.com/darkqiank/whois"
	"github.com/darkqiank/whois/server"
	"github.com/gofiber/fiber/v2"
	"log"
	"os"
)

func main() {
	// 定义命令行参数
	// 第一个参数是命令行标志的名字，第二个参数是默认值，第三个参数是使用说明

	// whois服务config路径
	serversPath := flag.String("s", "", "Path to the servers file.")

	// rdap服务config路径
	rdapPath := flag.String("r", "", "Path to the rdap file. set online to init from iana")

	// 新增端口号命令行参数
	server_port := flag.String("p", "8080", "Port on which the server will run.")

	// 解析命令行参数
	flag.Parse()

	whois.InitWhois(*serversPath)
	whois.InitRDAP(*rdapPath)

	app := fiber.New()

	// RDAP路由
	app.Get("/rdap/*", server.RdapHandler)

	// Whois路由，匹配/ref/*和其他所有情况
	app.Get("/*", server.WhoisHandler)

	// Choose the port to start server on
	port := os.Getenv("PORT")
	if port == "" {
		port = *server_port
	}

	serverAddress := fmt.Sprintf(":%s", port)

	asciiArt := `
__          ___             _____        _  ___  
\ \        / / |           |  __ \      | ||__ \ 
 \ \  /\  / /| |__   ___   | |  | | __ _| |_  ) |
  \ \/  \/ / | '_ \ / _ \  | |  | |/ _` + "`" + ` | __|/ / 
   \  /\  /  | | | | (_) | | |__| | (_| | |_|_|  
    \/  \/   |_| |_|\___/  |_____/ \__,_|\__(_)																							
`
	log.Println(asciiArt)
	log.Printf("\nWelcome to Who-Dat - WHOIS Lookup Service.\nApp up and running at %s", serverAddress)

	// Start fasthttp server
	if err := app.Listen(serverAddress); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
	}
}
