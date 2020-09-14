package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/spf13/cast"
	syslog "gopkg.in/mcuadros/go-syslog.v2"
)

var (
	myExp = regexp.MustCompile(`\s*\[(?P<rule>[0-9A-Za-z\_\-]*)\]\s*?IN=(?P<in>[[:alnum:]]*)\s+?OUT=(?P<out>[[:alnum:]]*)\s+?MAC=(?P<mac>[0-9A-Za-z\:\_\-]*)\s+?SRC=(?P<src>[0-9A-Za-z\.]*)\s+?DST=(?P<dst>[0-9A-Za-z\.]*)\s+?.*PROTO=(?P<proto>[A-Za-z]*)\s+?(?P<ports>SPT=*(?P<spt>[0-9]*)\s+?DPT=*(?P<dpt>[0-9]*))*`)

	db *sql.DB
)

func main() {
	SQLServer := flag.String("SqlServer", "", "Address of the Sql Server.")
	SQLPort := flag.Int("Port", 1433, "Port of the Sql Server.")
	SQLDatabase := flag.String("Database", "", "Database where logs are written to.")
	DBUsername := flag.String("Username", "", "Username to connect to Sql Server Database.")
	DBPassword := flag.String("Password", "", "Password to connect to Sql Server Database.")
	flag.Parse()

	// Build connection string
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s;",
		*SQLServer, *DBUsername, *DBPassword, *SQLPort, *SQLDatabase)

	var err error

	// Create connection pool
	db, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
	}
	ctx := context.Background()
	err = db.PingContext(ctx)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("Connected!\n")

	// Syslog connection
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.Boot()

	// https://serverfault.com/questions/463397/understanding-log-messages-from-iptables
	// https://logi.cc/en/2010/07/netfilter-log-format/

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			fmt.Println("<--->")
			fmt.Printf("len: %v\n", len(logParts))
			for key, value := range logParts { // Order not specified
				fmt.Printf("%v: %v\n", key, value)
			}
			fmt.Println(logParts["content"])

			match := myExp.FindStringSubmatch(cast.ToString(logParts["content"]))
			result := make(map[string]string)

			for i, name := range myExp.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}

			if len(result) != 0 {
				r := result["rule"]
				l := len(r)
				m := r[l-1:]
				var act string
				switch m {
				case "A":
					act = "ACCEPT"
				case "D":
					act = "DROP"
				case "R":
					act = "REJECT"
				default:
					act = "unknown"
				}

				fmt.Printf("rule:   %s\n", result["rule"])
				fmt.Printf("action: %v\n", act)
				fmt.Printf("in:     %s\n", result["in"])
				fmt.Printf("out:    %s\n", result["out"])
				fmt.Printf("mac:    %s\n", result["mac"])
				fmt.Printf("src:    %s\n", result["src"])
				fmt.Printf("dst:    %s\n", result["dst"])
				fmt.Printf("proto:  %s\n", result["proto"])
				fmt.Printf("spt:    %s\n", result["spt"])
				fmt.Printf("dpt:    %s\n", result["dpt"])

				ts := logParts["timestamp"].(time.Time)
				setTimeZone(&ts)

				// Create syslog record
				createID, err := CreateSyslog(
					ts,
					cast.ToString(logParts["hostname"]),
					cast.ToString(logParts["client"]),
					cast.ToInt(logParts["priority"]),
					cast.ToInt(logParts["severity"]),
					cast.ToString(logParts["tls_peer"]),
					cast.ToString(logParts["tag"]),
					cast.ToInt(logParts["facility"]),

					cast.ToString(result["rule"]),
					cast.ToString(act),
					cast.ToString(result["in"]),
					cast.ToString(result["out"]),
					cast.ToString(result["mac"]),
					cast.ToString(result["src"]),
					cast.ToString(result["dst"]),
					cast.ToString(result["proto"]),
					cast.ToInt(result["spt"]),
					cast.ToInt(result["dpt"]),
				)
				if err != nil {
					log.Fatal("Error creating syslog record: ", err.Error())
				}
				fmt.Printf("Inserted ID: %d successfully.\n", createID)
				fmt.Println()

			}
		}
	}(channel)

	server.Wait()
}

// CreateSyslog inserts a Syslog record into the database.
func CreateSyslog(
	timestamp time.Time,
	hostname string,
	client string,
	priority int,
	severity int,
	tlsPeer string,
	tag string,
	facility int,

	rule string,
	action string,
	in string,
	out string,
	mac string,
	src string,
	dst string,
	proto string,
	spt int,
	dpt int,
) (int64, error) {

	ctx := context.Background()
	var err error

	if db == nil {
		err = errors.New("CreateSyslog: db is null")
		return -1, err
	}

	// Check if database is alive.
	err = db.PingContext(ctx)
	if err != nil {
		return -1, err
	}

	tsql := "INSERT INTO dbo.Logs (Timestamp,hostname,client,priority,severity,tls_peer,tag,facility,fw_rule,action,interface_in,interface_out,mac,src,dst,proto,spt,dpt) VALUES (@Timestamp,@hostname,@client, @priority, @severity, @tlsPeer, @tag, @facility, @fw_rule, @action, @interface_in, @interface_out, @mac, @src, @dst, @proto, @spt, @dpt); select convert(bigint, SCOPE_IDENTITY());"

	stmt, err := db.Prepare(tsql)
	if err != nil {
		return -1, err
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(
		ctx,
		sql.Named("Timestamp", timestamp),
		sql.Named("hostname", hostname),
		sql.Named("client", client),
		sql.Named("priority", priority),
		sql.Named("severity", severity),
		sql.Named("tlsPeer", tlsPeer),
		sql.Named("tag", tag),
		sql.Named("facility", facility),

		sql.Named("fw_rule", rule),
		sql.Named("action", action),
		sql.Named("interface_in", in),
		sql.Named("interface_out", out),
		sql.Named("mac", mac),
		sql.Named("src", src),
		sql.Named("dst", dst),
		sql.Named("proto", proto),
		sql.Named("spt", spt),
		sql.Named("dpt", dpt),
	)
	var newID int64
	err = row.Scan(&newID)
	if err != nil {
		return -1, err
	}

	return newID, nil
}

func setTimeZone(ts *time.Time) {
	zone, err := time.LoadLocation("Local")
	if err != nil {
		log.Fatal("Failed to get timezone.")
	}

	newTs := time.Date(ts.Year(), ts.Month(), ts.Day(), ts.Hour(),
		ts.Minute(), ts.Second(), ts.Nanosecond(), zone)

	*ts = newTs
}
