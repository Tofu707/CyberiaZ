package main

import (
	"bufio"
	"container/list"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func init() {
	messageCache = list.New()
}
func main() {
	// whitelist, err := loadPubkeyList("whitelist.txt")
	// if err != nil {
	// 	log.Printf("Error loading whitelist: %v", err)
	// 	return
	// }

	// blacklist, err := loadPubkeyList("blacklist.txt")
	// if err != nil {
	// 	log.Printf("Error loading blacklist: %v", err)
	// 	return
	// }

	db := initSqliteDB()
	if db == nil {
		log.Panic("couldn't load main db")
		return
	}
	defer db.Close()
	initBoardSchema(db)

	var privateKeyPath string
	flag.StringVar(&privateKeyPath, "key", "./keys/ssh_host_ed25519_key", "Path to the private key")
	flag.Parse()
	if _, err := os.Stat("./keys"); os.IsNotExist(err) {
		fmt.Println("Error: ./keys directory does not exist. Please create it and generate an ed25519 keypair.")
		return
	}
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		fmt.Printf("Error: private key file %s does not exist. Please generate an ed25519 keypair.\n", privateKeyPath)
		return
	}
	users = make(map[string]*user)
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <port>\n", os.Args[0])
		return
	}
	config, err := configureSSHServer(privateKeyPath)
	if err != nil {
		fmt.Println("Error configuring SSH server:", err.Error())
		return
	}

	listener, err := net.Listen("tcp", ":"+os.Args[1])
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()
	fmt.Println("Listening on :" + os.Args[1])

	go api(db)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				fmt.Println("Error upgrading connection to SSH:", err.Error())
				return
			}
			defer sshConn.Close()
			go ssh.DiscardRequests(reqs)
			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					fmt.Println("Error accepting channel:", err.Error())
					return
				}
				// go handleConnection(db, channel, sshConn, requests, whitelist, blacklist)
				go handleConnection(db, channel, sshConn, requests)
			}
		}(conn)
	}
}

// func handleConnection(db *sqlx.DB, channel ssh.Channel, sshConn *ssh.ServerConn, requests <-chan *ssh.Request, whitelist map[string]bool, blacklist map[string]bool) {
func handleConnection(db *sqlx.DB, channel ssh.Channel, sshConn *ssh.ServerConn, requests <-chan *ssh.Request) {
	defer channel.Close()
	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		fmt.Fprintln(channel, "获取公钥失败！")
		return
	}
	pubkey, ok := sshConn.Permissions.Extensions["pubkey"]
	if !ok {
		fmt.Fprintln(channel, "获取公钥失败！")
		return
	}
	hash := formatUsernameFromPubkey(pubkey)

	// if _, ok := whitelist[hash]; !ok {
	// 	fmt.Fprintln(channel, "公钥在白名单中。欢迎回家！")
	// 	disconnect(hash)
	// 	return
	// }

	// if _, ok := blacklist[hash]; ok {
	// 	fmt.Fprintln(channel, "您被移出了服务器")
	// 	disconnect(hash)
	// 	return
	// }

	addUser(hash, &user{Pubkey: pubkey, Hash: hash, Conn: channel})

	term := term.NewTerminal(channel, "")
	term.SetPrompt("")
	saveCursorPos(channel)

	restoreCursorPos(channel)

	welcome := welcomeMessageAscii()

	term.Write([]byte(welcome))
	// 我不太喜欢进去就吐一堆MOTD
	// printMOTD(loadMOTD(motdFilePath), term)
	printCachedMessages(term)
	term.Write([]byte("\n欢迎 :) 你是 " + hash + "\n"))
	for {
		input, err := term.ReadLine()
		if err != nil {
			if err == io.EOF {
				disconnect(hash)
				return
			}
			readlineErrCheck(term, err, hash)
			return
		}

		switch {
		case strings.HasPrefix(input, "/ignore"):
			handleIgnore(input, term, hash)
		case strings.HasPrefix(input, "/help") || strings.HasPrefix(input, "/h"):
			writeHelpMenu(term)
		case strings.HasPrefix(input, "/license"):
			writeLicenseProse(term)
		case strings.HasPrefix(input, "/version"):
			writeVersionInfo(term)
		case strings.HasPrefix(input, "/users") || strings.HasPrefix(input, "/u"):
			writeUsersOnline(term)
		case strings.HasPrefix(input, "/bulletiners") || strings.HasPrefix(input, "/motd"):
			printMOTD(loadMOTD(motdFilePath), term)
		case strings.HasPrefix(input, "/pubkey"):
			term.Write([]byte("Your pubkey hash: " + hash + "\n"))
		case strings.HasPrefix(input, "/message") || strings.HasPrefix(input, "/say"):
			handleMessage(input, term, hash)
		case strings.HasPrefix(input, "/post") || strings.HasPrefix(input, "/p"):
			handlePost(input, term, db, hash)
		case strings.HasPrefix(input, "/list") || strings.HasPrefix(input, "/l"):
			listDiscussions(db, term)
		case strings.HasPrefix(input, "/history") || strings.HasPrefix(input, "/his"):
			printCachedMessages(term)
		case strings.HasPrefix(input, "/tokens new"):
			handleTokenNew(db, term, hash)
		case strings.HasPrefix(input, "/tokens list"):
			handleTokenList(db, term, hash)
		case strings.HasPrefix(input, "/tokens revoke"):
			handleTokenRevoke(db, input, term, hash)
		case strings.HasPrefix(input, "/quit") || strings.HasPrefix(input, "/q") ||
			strings.HasPrefix(input, "/exit") || strings.HasPrefix(input, "/x") ||
			strings.HasPrefix(input, "/leave") || strings.HasPrefix(input, "/part"):
			disconnect(hash)
		case strings.HasPrefix(input, "/replies") || strings.HasPrefix(input, "/rs"):
			handleReplies(input, term, db)
		case strings.HasPrefix(input, "/reply") || strings.HasPrefix(input, "/r"):
			err := handleReply(input, term, db, hash)
			if err != nil {
				term.Write([]byte(err.Error() + "\n"))
			}
		case strings.HasPrefix(input, "/build"):
			writegithub(term)
		default:
			if len(input) > 0 {
				if strings.HasPrefix(input, "/") {
					term.Write([]byte("未知的命令。输入 /help 查看可用指令\n"))
				} else {
					message := fmt.Sprintf("[%s] %s: %s", time.Now().String()[11:16], hash, input)
					broadcast(hash, message)
				}
			}
		}
	}
}

// func loadPubkeyList(filename string) (map[string]bool, error) {
// 	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
// 	if err != nil {
// 		return nil, fmt.Errorf("unable to open %s: %v", filename, err)
// 	}
// 	defer file.Close()

// 	pubkeyList := make(map[string]bool)

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		pubkey := scanner.Text()
// 		pubkeyList[pubkey] = true
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return nil, fmt.Errorf("error reading %s: %v", filename, err)
// 	}

// 	return pubkeyList, nil
// }

func saveCursorPos(channel ssh.Channel) {
	writeString(channel, "\033[s")
}

func restoreCursorPos(channel ssh.Channel) {
	writeString(channel, "\033[u")
}

func moveCursorUp(channel ssh.Channel, n int) {
	writeString(channel, fmt.Sprintf("\033[%dA", n))
}
func moveCursorDown(w io.Writer, lines int) {
	fmt.Fprintf(w, "\033[%dB", lines)
}
func writeString(channel ssh.Channel, s string) {
	channel.Write([]byte(s))
}

func generateHash(pubkey string) string {
	h := sha3.NewShake256()
	h.Write([]byte(pubkey))
	checksum := make([]byte, 16)
	h.Read(checksum)
	return base64.StdEncoding.EncodeToString(checksum)
}

func disconnect(hash string) {
	usersMutex.Lock()
	user, exists := users[hash]
	usersMutex.Unlock()

	if exists {
		user.Conn.Close()
	}

	removeUser(hash)
}

func broadcast(senderHash, message string) {
	addToCache(message)
	for _, user := range getAllUsers() {
//		if user.Hash == senderHash {
//			continue
//		}
		saveCursorPos(user.Conn)
		moveCursorUp(user.Conn, 1)
		fmt.Fprintln(user.Conn, message)
		restoreCursorPos(user.Conn)
		moveCursorDown(user.Conn, 1)
		fmt.Fprint(user.Conn, "\n")
		if user.Conn == nil {
			log.Printf("broadcast: user with hash %v has nil connection\n", user.Hash)
			continue
		}
		log.Printf("Broadcasted message to user with hash %v\n", user.Hash)
	}
}

func isPostNumberExist(db *sqlx.DB, postNum int) (bool, error) {
	var count int
	err := db.Get(&count, "SELECT COUNT(*) FROM discussions WHERE id = ?", postNum)
	if err != nil {
		return false, err
	}
	if count <= 0 {
		return false, nil
	} else {
		return true, nil
	}
}

func addDiscussion(db *sqlx.DB, author, message string) int {
	res, err := db.Exec("INSERT INTO discussions (author, message) VALUES (?, ?)", author, message)
	if err != nil {
		log.Println(err)
		return -1
	}
	id, err := res.LastInsertId()
	if err != nil {
		log.Println(err)
		return -1
	}
	return int(id)
}

func addReply(db *sqlx.DB, postNumber int, author, message string) bool {
	_, err := db.Exec("INSERT INTO replies (discussion_id, author, message) VALUES (?, ?, ?)", postNumber, author, message)
	if err != nil {
		log.Println(err)
		return false
	}
	return true

}

func listDiscussions(db *sqlx.DB, term *term.Terminal) {
	var discussions []struct {
		ID         int    `db:"id"`
		Author     string `db:"author"`
		Message    string `db:"message"`
		ReplyCount int    `db:"reply_count"`
	}
	err := db.Select(&discussions, `
		SELECT d.id, d.author, d.message, COUNT(r.id) as reply_count
		FROM discussions d
		LEFT JOIN replies r ON d.id = r.discussion_id
		GROUP BY d.id
	`)
	if err != nil {
		log.Printf("Error retrieving discussions: %v", err)
		term.Write([]byte("获取讨论板失败。\n"))
		return
	}

	sort.Slice(discussions, func(i, j int) bool {
		weightID := 0.3
		weightReplyCount := 0.7

		scoreI := weightID*float64(discussions[i].ID) + weightReplyCount*float64(discussions[i].ReplyCount)
		scoreJ := weightID*float64(discussions[j].ID) + weightReplyCount*float64(discussions[j].ReplyCount)

		return scoreI > scoreJ
	})

	term.Write([]byte("讨论板:\n\n[序号.]\t[💬回复数]\t[主题]\n\n"))
	for _, disc := range discussions {
		term.Write([]byte(fmt.Sprintf("%d.\t💬%d\t[%s] %s\n", disc.ID, disc.ReplyCount, disc.Author, disc.Message)))
	}
}

func listReplies(db *sqlx.DB, postNumber int, term *term.Terminal) {
	var disc discussion
	err := db.Get(&disc, "SELECT id, author, message FROM discussions WHERE id = ?", postNumber)
	if err != nil {
		log.Printf("Error retrieving discussion: %v", err)
		term.Write([]byte("错误的讨论序号\n"))
		return
	}
	term.Write([]byte(fmt.Sprintf("讨论 %d [%s] 的回复:\n", disc.ID, disc.Author)))

	var replies []*reply
	err = db.Select(&replies, "SELECT author, message FROM replies WHERE discussion_id = ?", postNumber)
	if err != nil {
		log.Printf("Error retrieving replies: %v", err)
		term.Write([]byte("获取回复失败。\n"))
		return
	}
	for i, rep := range replies {
		term.Write([]byte(fmt.Sprintf("%d. [%s] %s\n", i+1, rep.Author, rep.Message)))
	}
}

func addToCache(message string) {
	messageCache.PushBack(message)
	if messageCache.Len() > 100 {
		messageCache.Remove(messageCache.Front())
	}
}

func printCachedMessages(term *term.Terminal) {
	for e := messageCache.Front(); e != nil; e = e.Next() {
		term.Write([]byte(e.Value.(string) + "\r\n"))
	}
}
func printMOTD(motd string, term *term.Terminal) {
	if motd != "" {
		term.Write([]byte(motd + "\r\n"))
	}

}

func configureSSHServer(privateKeyPath string) (*ssh.ServerConfig, error) {
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Printf("Received public key of type %s from user %s\n", key.Type(), conn.User())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey": string(key.Marshal()),
				},
			}, nil
		},
	}
	config.AddHostKey(privateKey)
	return config, nil
}

func addUser(hash string, u *user) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	u.Ignored = make(map[string]bool)
	users[hash] = u
}

func removeUser(hash string) {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	delete(users, hash)
}

func getAllUsers() []*user {
	usersMutex.Lock()
	defer usersMutex.Unlock()
	allUsers := make([]*user, 0, len(users))
	for _, user := range users {
		allUsers = append(allUsers, user)
	}
	return allUsers
}

func cleanString(dirtyString string) (string, error) {
	var clean strings.Builder
	for _, r := range dirtyString {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			clean.WriteRune(r)
		}
	}

	if clean.Len() < 8 {
		return "", errors.New("not enough characters after cleaning")
	}

	return clean.String()[:8], nil
}

func sendMessage(senderHash, recipientHash, message string, term *term.Terminal) {
	usersMutex.Lock()
	recipient, ok := users[recipientHash]
	usersMutex.Unlock()
	if !ok {
		fmt.Fprintf(users[senderHash].Conn, "\n\rUser with hash %s not found\n", recipientHash)
		return
	}
	if recipient.Ignored[senderHash] {
		return
	}
	message = "\r\n[DirectMessage][" + senderHash + "] " + message + "\r\n"
	fmt.Fprintln(recipient.Conn, message)
	term.Write([]byte(message))
}

func loadMOTD(motdFilePath string) string {

	var motdMessage string
	file, err := os.Open(motdFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			os.Create(motdFilePath)
			if err != nil {
				log.Println("we weren't able to create it either: " + err.Error())
				return ""
			}
			log.Println("motd didn't exist: " + err.Error())
			return ""
		}
		log.Println("error opening motdFilePath: " + err.Error())
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			motdMessage += line + "\n"
		}
	}

	return motdMessage
}

func handleReply(input string, term *term.Terminal, db *sqlx.DB, hash string) error {
	parts := strings.SplitN(input, " ", 3)
	if len(parts) < 3 {
		return fmt.Errorf("usage: /reply <post number> <reply body>")
	}
	postNum, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid post number. Usage: /reply <post number> <reply body>")
	}
	exists, err := isPostNumberExist(db, postNum)
	if err != nil {
		return fmt.Errorf("failed to check post number: %v", err)
	}
    // log.Println(exists)
	if !exists {
	//	log.Println("not exists")
		return fmt.Errorf("invalid post number. Post number %d does not exist. Usage: /reply <post number> <reply body>", postNum)
	}
	replyBody := parts[2]
	replySuccess := addReply(db, postNum, hash, replyBody)
	if !replySuccess {
		return fmt.Errorf("failed to reply to post. Please check the post number and try again")
	} else {
		term.Write([]byte("您的回复已成功发布。\n"))
		return nil
	}
}

func handleReplies(input string, term *term.Terminal, db *sqlx.DB) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		term.Write([]byte("用法: /replies <post number>\n"))
		return
	}
	postNum, err := strconv.Atoi(parts[1])
	if err != nil {
		term.Write([]byte("错误的帖子序号. 用法: /replies <post number>\n"))
		return
	}
	listReplies(db, postNum, term)
}

func handleIgnore(input string, term *term.Terminal, hash string) {
	parts := strings.Split(input, " ")
	if len(parts) != 2 {
		term.Write([]byte("用法: /ignore <user hash>\n"))
		return
	}
	ignoredUser := parts[1]
	usersMutex.Lock()
	_, exists := users[ignoredUser]
	usersMutex.Unlock()
	if !exists {
		term.Write([]byte("未找到用户 " + ignoredUser + " 。\n"))
	} else if ignoredUser == hash {
		term.Write([]byte("你不能忽略自己。\n"))
	} else {
		users[hash].Ignored[ignoredUser] = true
		term.Write([]byte("成功忽略用户 " + ignoredUser + " 。\n"))
	}
}

func readlineErrCheck(term *term.Terminal, err error, hash string) {
	term.Write([]byte("读取输入失败: "))
	term.Write([]byte(err.Error()))
	term.Write([]byte("\n"))
	disconnect(hash)
}

func handlePost(input string, term *term.Terminal, db *sqlx.DB, hash string) {
	parts := strings.SplitN(input, " ", 2)
	if len(parts) < 2 {
		term.Write([]byte("用法: /post <message>\n"))
	} else {
		postNumber := addDiscussion(db, hash, parts[1])
		term.Write([]byte(fmt.Sprintf("成功投递讨论，序号为：%d。\n", postNumber)))
	}
}

func handleMessage(input string, term *term.Terminal, hash string) {
	parts := strings.Split(input, " ")
	if len(parts) < 3 {
		term.Write([]byte("用法: /message <user hash> <direct message text>\n"))
	} else {
		recipientHash := parts[1]
		message := strings.Join(parts[2:], " ")
		sendMessage(hash, recipientHash, message, term)
	}
}

func formatUsernameFromPubkey(pubkey string) string {
	hash, err := cleanString(generateHash(pubkey))
	if err != nil {
		log.Println("生成用户名错误: ", err)
	}
	hash = "@" + hash
	return hash
}

func welcomeMessageAscii() string {
	welcome := `

 ____________________
|ZZZZZZZZZZZZZZZZZZZZ|
────────────────/ZZZ/
・・・・・・・・/ZZZ/・・
・・・・・・・/ZZZ/・・・
・・・・・・/ZZZ/・・・・
・・・・・/ZZZ/・・・・・
・・・・/ZZZ/・・・・・・
・・・/ZZZ/・・・・・・・
・・/ZZZ/・・・・・・・・
・/ZZZ/・・・・・・・・・
|ZZZ/________________
|ZZZZZZZZZZZZZZZZZZZZ|
 ────────────────────


}
> MIT 2023, https://github.com/donuts-are-good/shhhbb ` + semverInfo + `   

> Hello Navi, we are here again.

 [规 则]                         [目 标]
  - 畅所欲言                       - 为Zekkers搭建一个复古平台
  - 分享知识                       - 搞点有意思的事儿
  - 别做坏事                       - 学习共进
  - 享受乐趣! :)                   - 逃离现代互联网

输入hello，按下回车，开始聊天！
输入 /help 获取完整的命令提示。

`
	return welcome
}

func writeUsersOnline(term *term.Terminal) {
	term.Write([]byte("已连接的用户:\n"))
	for _, user := range users {
		term.Write([]byte("- " + user.Hash + "\n"))
	}
}
func writegithub(term *term.Terminal) {
	term.Write([]byte(`
CyberiaZ是shhhbb的一个folk，使用了GO语言。
因为是开源的，你也可以通过git为CyberiaZ添加自己喜欢的功能。

CyberiaZ项目主页: 
https://github.com/Tofu707/CyberiaZ
` + "\n"))
}
func writeHelpMenu(term *term.Terminal) {
	term.Write([]byte(`
[一般 | General Commands]
	/help, /h		
		- 显示这个帮助 | show this help message
	/pubkey, /pub		
		- 显示您的公钥（同时也是用户名） | show your pubkey hash, which is also your username
	/users, /u		
		- 列出所有在线用户 | list all online users
	/message(/say) <user hash> <body> 
		- 使用例: /message @A1Gla593 你好呀 | ex: /message @A1Gla593 hey there friend
		- 发送私密消息给指定用户
	/quit, /q, /exit, /x
		- 退出服务器。拜拜！ | disconnect, exit, goodbye

[聊天 | Chat commands]
	/history, /his
		- 显示过去100条聊天历史 | reloads the last 100 lines of chat history

[公告板 | Message Board]
	/post(/p) <message>
		- 使用例: /post 超酷的标题 | ex: /post this is my cool title
		- 创建一个新讨论 | posts a new discussion topic 
	/list, /l
		- 列出所有讨论 | list all discussions 
	/replies(/rs) <post number>
		- 使用例: /replies 1 | ex: /replies 1
		- 列出某个讨论的所有回复 | list all replies to a discussion
	/reply(/r) <post number> <reply body>
		- ex: /reply 1 hello everyone
		- reply to a discussion

[API(暂时未知如何使用) | API Commands]
	/tokens new
		- create a new shhhbb API token 
	/tokens list
		- view your shhhbb API tokens
	/tokens revoke <token>
		- revoke an shhhbb API token

[杂项 | Misc. Commands]
	/license
		- display the license text for shhhbb 
	/version
		- display the shhhbb version information	
	/build
		- 显示这个项目的github。欢迎您的贡献！
	
` + "\n"))
}
func writeLicenseProse(term *term.Terminal) {
	term.Write([]byte(`
MIT License
Copyright (c) 2023 donuts-are-good https://github.com/donuts-are-good
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`))
}
func writeVersionInfo(term *term.Terminal) {
	term.Write([]byte(`
CyberiaZ bbs v1.0 (2024.10.7)
s基于hhhbb bbs ` + semverInfo + `
MIT License 2023 donuts-are-good
https://github.com/donuts-are-good/shhhbb
`))
}
