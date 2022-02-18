package main

import "C"
import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/cypherium/cypherBFT/common"
	//"github.com/cypherium/cypherBFT/common/hexutil"
	//"github.com/cypherium/cypherBFT/core/types"
	"github.com/cypherium/cypherBFT/metrics"
	"github.com/mikemintang/go-curl"
	"gopkg.in/urfave/cli.v1"
	"net"
)

//-------使用说明--------//
/*---------------------
1、在使用前，需要服务器节点的run.sh文件的--rpcapi改成--rpcapi cph,web3,personal,miner,admin,net,txpool
2、rpcnodes.json为ip,public,coinbase的所有对应关系，需要编辑或生成相应文件放在工程根目录下。
3、在cmd/tool/下执行,go build rpcctl.go
4、运行./rpcctl 命令
5、加--ip的时候为指定特定的ip,多个ip永逗号隔开
 ---------------------*/
const (
	relativepath = "./../../"
)
const (
	hostsfile               = "hostnametest.txt"
	rpcjsonfile             = "grpcoutputtest.json"
	genesisoutputfile       = "genesisoutputtest.json"
	genesiscommonoutputfile = "genesiscommonoutputtest.json"
	accountsfile            = "accounts.txt"
	genesis                 = "genesistest.json"
)

const (
	DFONETPORT = 7100
	DFRPCPORT  = 8000 //8000
	ALLOCCOIN  = "10000000000000000000000000"
)

const (
	suitevale    = "Ed25519"
	MemberStatus = "member"
	LeaderStatus = "leader"
)

const (
	MULRADIX = 2
	MINNODES = 4
)
const (
	BlsPubkeyLength = 64
)

type jsonrsp struct {
	jsonrpc string   `json:"jsonrpc"    gencodec:"required"`
	id      string   `json:"id"         gencodec:"required"`
	result  []string `json:"result"      gencodec:"required"`
}

const (
	URL      = "address"
	COINBASE = "coinbase"
	PUBLIC   = "public"
	DES      = "description"
	SUITE    = "suite"
)
const (
	CNODEDES    = "Cnode_"
	GNODEDES    = "Gnode_"
	BNODEDES    = "Bnode_"
	ALLNODESDES = "Anode"
)
const (
	DFIDX       = "0"
	DFLEADERIDX = DFIDX
)

const (
	LOCALPREFIX = "local"
)
const (
	HEXPREFIX = "0x"
)

const (
	ACCOUNTPREFIX = "#"
)

const (
	GNODE    = "0"
	CNODE    = "1"
	LNODE    = "2"
	ALLNODES = "3"
)
const (
	DISABLE = "0"
	ENABLE  = "1"
)

var remotIndValue = -1

const (
	DFPASSWD = "1"
)
const (
	DFTIME = 100
)

const (
	LOCALIP = "1" //代表127.0.0.1
)

const (
	GENJSMAP            = "genJsMap"
	MINERSTART          = "miner_start"
	MINERSTOP           = "miner_stop"
	MINERSTATUS         = "miner_status"
	ACCOUNTS            = "eth_accounts"
	KEYBLKNUM           = "eth_keyBlockNumber"
	TXBLKNUM            = "eth_txBlockNumber"
	PEERS               = "admin_peers"
	UNLOCKALL           = "personal_unlockAll"
	PEERCOUNT           = "net_peerCount"
	AUTOTRANS           = "eth_autoTransaction"
	TXPOOLSATUS         = "txpool_status"
	TXPOOLINSPECT       = "txpool_inspect"
	GETBALANCE          = "eth_getBalance"
	SENDTRANS           = "eth_sendTransaction"
	ROSTERCONFIG        = "eth_rosterConfig"
	MANUALRECONFIGSTART = "eth_manualReconfigStart"
	MANUALRECONFIGSTOP  = "eth_manualReconfigStop"
	FINDIDX             = "fdidx"
)

type genesisHeader struct {
	Address  string `json:"address" gencodec:"required"`
	CoinBase string `json:"coinbase" gencodec:"required"`
	Public   string `json:"public" gencodec:"required"`
}

type genesisCommonHeader struct {
	CoinBase string `json:"coinbase" gencodec:"required"`
	Public   string `json:"public" gencodec:"required"`
}

type rpcHeader struct {
	Address     string `json:"address" gencodec:"required"`
	CoinBase    string `json:"coinbase" gencodec:"required"`
	Public      string `json:"public" gencodec:"required"`
	Description string `json:"description" gencodec:"required"`
}
type Coin struct {
	Balance string `json:"balance" gencodec:"required"`
}
type AllocCoin struct {
	allocCoinNodes map[string]Coin
}
type genesitNode struct {
	Index  string
	Header rpcHeader
}

type RpcNodes struct {
	nodes map[string]rpcHeader
}

type EpochKeyPair struct {
	EpochPubKey string `json:"epochPubKey" gencodec:"required"`
	EpochPriKey string `json:"epochPriKey" gencodec:"required"`
}
type genesisNode struct {
	Index  string
	Header rpcHeader
}

var PreFixStr = LOCALPREFIX

type isLocalIndex struct {
	isLocal   bool
	Index     int
	PreFixStr string
}
type genesisNodes struct {
	nodes map[string]genesisHeader
}

type genesisCommonNodes struct {
	nodes map[string]genesisCommonHeader
}

var (
	RpcPortFlag = cli.IntFlag{
		Name:  "port",
		Usage: "--port 18002",
		Value: DFRPCPORT,
	}
	RpcRoleFlag = cli.StringFlag{
		Name:  "role",
		Usage: "--role 1", //0 for committeemember node,1 for general node
		Value: GNODE,
	}
	RpcIpFlag = cli.StringFlag{
		Name:  "ip",
		Usage: "--ip 208.43.19.151 ", //0 for committeemember node,1 for general node
		Value: "",
	}
	RpcEnableFlag = cli.StringFlag{
		Name:  "en",
		Usage: "--en 1", //0 for disable ,1 for enable
		Value: ENABLE,
	}
	SortEnableFlag = cli.StringFlag{
		Name:  "sort",
		Usage: "--sort 1", //0 for disable ,1 for enable
		Value: DISABLE,
	}
	StartIndexFlag = cli.IntFlag{
		Name:  "sIdx",
		Usage: "--sIdx 1",
		Value: 0,
	}
	RpcJsLocalFlag = cli.StringFlag{
		Name:  "local",
		Usage: "--local 1", //0 for disable ,1 for enable
		Value: DISABLE,
	}

	RpcnodeIdxChangeFlag = cli.StringFlag{
		Name:  "idxCg",
		Usage: "--idxCg 1", //0 for disable ,1 for enable
		Value: DISABLE,
	}

	RpcNodeIndexFlag = cli.IntFlag{
		Name:  "idx",
		Usage: "--idx 1",
		Value: -1,
	}

	RpcLeaderIndexFlag = cli.IntFlag{
		Name:  "lIdx",
		Usage: "--lIdx 0",
		Value: 0,
	}
	RpcTimeFlag = cli.IntFlag{
		Name:  "time",
		Usage: "--time 100",
		Value: DFTIME,
	}
	CommonFlag = cli.IntFlag{
		Name:  "common",
		Usage: "--common 1",
		Value: 0,
	}
	RpcPasswdFlag = cli.StringFlag{
		Name:  "passwd",
		Usage: "--passwd 1",
		Value: DFPASSWD,
	}
	PreFixNameFlag = cli.StringFlag{
		Name:  "preFix",
		Usage: "--preFix lan3",
		Value: LOCALPREFIX,
	}
	RpcTransPortFlag = cli.StringFlag{
		Name:  "trans",
		Usage: "--trans 18002",
		Value: strconv.Itoa(DFRPCPORT),
	}

	RpcAccountsFlag = cli.StringFlag{
		Name:  "accounts",
		Usage: "--accounts",
	}

	RpcCoinBaseFlag = cli.StringFlag{
		Name:  "coinbase",
		Usage: "--coinbase",
		Value: "",
	}
	RpcKeyBnrFlag = cli.StringFlag{
		Name:  "keyBnr",
		Usage: "--keyBnr",
		Value: "0x01",
	}
	RpcTxBnrFlag = cli.StringFlag{
		Name:  "txBnr",
		Usage: "--txBnr",
		Value: "0x01",
	}
	RpcFromFlag = cli.StringFlag{
		Name:  "from",
		Usage: "--from",
		Value: "461f9d24b10edca41c1d9296f971c5c028e6c64c",
	}
	RpcToFlag = cli.StringFlag{
		Name:  "to",
		Usage: "--to",
		Value: "01482d12a73186e9e0ac1421eb96381bbdcd4557",
	}
	RpcAmountFlag = cli.StringFlag{
		Name:  "amount",
		Usage: "--amount",
		Value: "100",
	}
	RpcCnodeNumFlag = cli.StringFlag{
		Name:  "cnum",
		Usage: "--cnum",
		Value: "4",
	}
)

/*----local command ------
//命令用于chaindb的accounts文件与IP文件自动生成genesis.json文件和rpcnodes.json文件
Name:   "genJsMap",      //   ./rpcctl genJsMap --cnum 4

----command ------------*/

/*----rpc command list------
Name:   "miner.start",./rpcctl miner.start --local 1 --role 3 同时开始挖矿 --ip可以指定远程地址，也可以指定本地地址(为1时代表127.0.0.1）
Name:   "miner.stop",
Name:   "miner.status",
Name:   "accounts",
Name:   "keyBlockNumber",
Name:   "txBlockNumber",
Name:   "unlockAll",
Name:   "peerCount",
Name:   "autoTrans",// ./rpcctl autoTrans --local 1 --en 1 --time 5 --ip可以指定远程地址，也可以指定本地地址(为1时代表127.0.0.1）

Name:   "peers",
Name:   "txPoolStatus",
Name:   "txPoolInspect",
Name:   "getBalance",     //  ./rpcctl getBalance --ip 67.228.187.206 --txBnr 0x2111 --coinbase 461f9d24b10edca41c1d9296f971c5c028e6c64c

----command list------*/

func main() {
	app := cli.NewApp()
	app.Name = "rpcctl"
	app.Usage = ""
	app.Commands = []cli.Command{
		{
			Name:  "genJsMap",
			Usage: "--local 1",
			//Flags:  []cli.Flag{RpcCnodeNumFlag, RpcJsLocalFlag, RpcLeaderIndexFlag},
			Flags:  []cli.Flag{CommonFlag, StartIndexFlag, SortEnableFlag, PreFixNameFlag, RpcJsLocalFlag, RpcLeaderIndexFlag, RpcnodeIdxChangeFlag, RpcCnodeNumFlag},
			Action: genJsMap,
		},
		{
			Name:   "miner.start",
			Usage:  "--role 0 --passwd 1 --ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcRoleFlag, RpcPasswdFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: minersStart,
		}, {
			Name:   "manualReconfig.start",
			Usage:  "--role 0 --passwd 1 --ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcRoleFlag, RpcPasswdFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: manualReconfigStart,
		},
		{
			Name:   "miner.stop",
			Usage:  "--role 0 --ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcRoleFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: minersStop,
		}, {
			Name:   "manualReconfig.stop",
			Usage:  "--role 0 --ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcRoleFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: manualReconfigStop,
		},

		{
			Name:   "miner.status",
			Usage:  "--role 0  --ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcRoleFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: minersStatus,
		},
		{
			Name:   "accounts",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcAccountsFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: cphAccounts,
		},

		{
			Name:   "keyBlockNumber",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: keyBlockNumber,
		},
		{
			Name:   "txBlockNumber",
			Usage:  " --ip 208.43.19.151 --port 18002 ",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: txBlockNumber,
		},
		{
			Name:   "unlockAll",
			Usage:  "--ip 208.43.19.151 --port 18002 --passwd 1",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcPasswdFlag, RpcJsLocalFlag},
			Action: personalUnlockAll,
		},
		{
			Name:   "peerCount",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: peerCount,
		},
		{
			Name:   "autoTrans",
			Usage:  "--ip 208.43.19.151 --port 18002 --en 1 --time 5 --passwd 1",
			Flags:  []cli.Flag{PreFixNameFlag, RpcPortFlag, RpcEnableFlag, RpcTimeFlag, RpcPasswdFlag, RpcIpFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: autoTransaction,
		},

		{
			Name:   "peers",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: peers,
		},
		{
			Name:   "txpool.status",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: txPoolStatus,
		},
		{
			Name:   "txpool.inspect",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: txPoolInspect,
		},
		{
			Name:   "getBalance",
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcCoinBaseFlag, RpcTxBnrFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: getBalance,
		},
		{
			Name:   "sendTrans", //some problem
			Usage:  "--ip 208.43.19.151 --port 18002",
			Flags:  []cli.Flag{PreFixNameFlag, RpcFromFlag, RpcToFlag, RpcAmountFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag},
			Action: sendTrans,
		}, {
			Name:  "getCommitteeLen", //some problem
			Usage: "./rpcctl getCommitteeLen --local 1",
			//Flags:  []cli.Flag{RpcRoleFlag, RpcFromFlag, RpcToFlag, RpcAmountFlag, RpcIpFlag, RpcPortFlag, RpcJsLocalFlag, RpcNodeIndexFlag, RpcLeaderIndexFlag, RpcCnodeNumFlag, RpcPasswdFlag, RpcnodeIdxChangeFlag},
			Flags:  []cli.Flag{PreFixNameFlag, RpcJsLocalFlag},
			Action: getCommitteeLen,
		}, {
			Name:   "fdidx",
			Usage:  "./rpcctl fdidx 192.168.0.168",
			Flags:  []cli.Flag{RpcIpFlag},
			Action: getCommitteeMemberIndex,
		},
		{
			Name: "tips:\r\n",
			Usage: "     you can specify a remote address or a local address; If you don't specify --ip，will be sent to all nodes\r\n" +
				"       --ip                                               --ip 34.218.44.251:remote node\r\n" +
				"       --local                                            mean will control local nodes \r\n" +
				"       --role                                             0 : miner 1:committee member 3:for all nodes \r\n" +
				"       --idx                                              mean the index of nodes readed form grpcoutput.json or localgrpcoutput.json \r\n" +
				"       --preFix                                              user define prefix name for chaindb and json files,default local\r\n" +
				"       --sIdx                                             local node genJsMap start idx,default 0\r\n" +
				"                                                          generally to point the specify node to do some action \r\n" +
				"                                                                                                                                          \r\n" +
				"      .============================================================REMOTE==================================================================\r\n" +
				"      .---------------------------------------------------generate remote rpc json file-----------------------------------------------------\r\n" +
				"      ./rpcctl genJsMap                                    mean not change current genesisLen,just edit cnodes'ip coinbase etc.\r\n" +
				"      ./rpcctl genJsMap  --common 1                        generate common node genesis                                \r\n" +
				"      ./rpcctl genJsMap  --idxCg 1 --cnum 7            mean change current genesisLen and set cnodes'ip coinbase etc.\r\n" +
				"      .----------------------------------------------------remote miner.start--------------------------------------------------------------\r\n" +
				"      ./rpcctl miner.start --role 1                       mean that all remote all committee nodes will start mining at the same time\r\n" +
				"      ./rpcctl miner.start --role 3                       mean that all remote nodes will start mining at the same time\r\n" +
				"      ./rpcctl miner.start --ip 34.218.44.251 --role 3  mean that remote node which it's ip is 34.218.44.251 start mining at the same time\r\n" +
				"      .----------------------------------------------------remote miner.stop---------------------------------------------------------------\r\n" +
				"      ./rpcctl miner.stop --role 1                         mean that all remote all committee nodes will stop mining at the same time\r\n" +
				"      ./rpcctl miner.stop --role 3                         mean that all remote nodes will stop mining at the same time\r\n" +
				"      ./rpcctl miner.stop --ip 34.218.44.251 --role 3  mean that remote node which it's ip is 34.218.44.251 stop mining at the same time\r\n" +
				"      .----------------------------------------------------remote autoTrans----------------------------------------------------------------\r\n" +
				"      ./rpcctl autoTrans --en 1 --time 10         mean remote node will start auto transaction, temporarily is leader's account[0]\r\n" +
				"      ./rpcctl autoTrans --en 1 --time 10 --idx 1  mean remotenode transfer, specify one node \r\n" +
				"      .----------------------------------------------------check status--------------------------------------------------------------------\r\n" +
				"      ./rpcctl miner.status                                mean all remote nodes reply their role status \r\n" +
				"      ./rpcctl keyBlockNumber                             mean all remote nodes reply their role keyBlockNumber\r\n" +
				"      ./rpcctl txBlockNumber                              mean all remote nodes reply their role txBlockNumber \r\n" +
				"      .---------------------------------------------------remote rosterConfig(contain manualReconfig start)-------------------------------\r\n" +
				"      ./rpcctl rosterConfig --role 3 --passwd 1  --idxCg 1     manual ReConfig for remote nodes\r\n" +
				"                                                                                                                                          \r\n" +
				"      .============================================================LOCAL==================================================================\r\n" +
				"      .---------------------------------------------------generate local rpc json file-----------------------------------------------------\r\n" +
				"      ./rpcctl genJsMap --local 1  --preFix lan1  --sIdx 9              mean not change current genesisLen,just edit cnodes'ip coinbase etc.\r\n" +
				"      ./rpcctl genJsMap --local 1 --idxCg 1 --cnum 9 --preFix lan1 --sIdx 9    mean change current genesisLen and set cnodes'ip coinbase etc.\r\n" +
				"      .---------------------------------------------------local miner.start-----------------------------------------------------------\r\n" +
				"      ./rpcctl miner.start --local 1 --role 3 --preFix lan1   mean that all local nodes start mining at the same time\r\n" +
				"      ./rpcctl miner.start --idx 1 --local 1 --preFix lan1    mean that the local node whose idx is 1 capture from localgrpcoutput.json will be started\r\n" +
				"      .---------------------------------------------------local miner.stop-----------------------------------------------------------\r\n" +
				"      ./rpcctl miner.stop --local 1  --preFix lan1                      mean that local miners stop mining at the same time\r\n" +
				"      .---------------------------------------------------local autoTrans-----------------------------------------------------------\r\n" +
				"      ./rpcctl autoTrans --local 1 --en 1 --time 100 --preFix lan1        mean local node transfer, temporarily is leader's account[0]\r\n" +
				"      ./rpcctl autoTrans --local 1 --en 1 --time 100 --idx 1      --preFix lan1 mean local node transfer, specify one node \r\n" +
				"      .---------------------------------------------------local rosterConfig(contain manualReconfig start)--------------------------------\r\n" +
				"      ./rpcctl rosterConfig --role 3 --local 1  --passwd 1  --idxCg 1  --preFix lan1            manual ReConfig for local nodes \r\n",

			Flags:  []cli.Flag{},
			Action: sendTrans,
		},
	}
	app.Run(os.Args)
}

func GetFilePath(fileName string) string {
	pwd, _ := os.Getwd()
	//fmt.Println("pre pwd",pwd)
	//pwd = strings.TrimLeft(pwd, "cmd/tools")
	pwd = strings.Replace(pwd, "cmd/tools", "", -1)
	//fmt.Println("after pwd",pwd)
	return pwd + "/" + fileName
}
func peerCount(c *cli.Context) error {

	return postMethod(c, PEERCOUNT)
}

func cphAccounts(c *cli.Context) error {

	return postMethod(c, ACCOUNTS)

}

func peers(c *cli.Context) error {

	return postMethod(c, PEERS)
}

func minersStatus(c *cli.Context) error {
	CommitteeMemberCount = 0
	return postMethod(c, MINERSTATUS)
}

func keyBlockNumber(c *cli.Context) error {
	return postMethod(c, KEYBLKNUM)
}
func txBlockNumber(c *cli.Context) error {
	return postMethod(c, TXBLKNUM)
}

func txPoolStatus(c *cli.Context) error {
	return postMethod(c, TXPOOLSATUS)
}
func txPoolInspect(c *cli.Context) error {
	return postMethod(c, TXPOOLINSPECT)
}

func getBalance(c *cli.Context) error {
	_, sIpString, _, _, _, _, _ := getPortIpsPassword(c)
	if sIpString == "" {

	} else {
		return postMethod(c, GETBALANCE)
	}
	return nil
}

func sendTrans(c *cli.Context) error {
	return postMethod(c, SENDTRANS)
}
func genJsMap(c *cli.Context) error {
	var committeeLen int
	PreFixStr = c.String(PreFixNameFlag.Name)
	isLocalJsMap := c.Int(RpcJsLocalFlag.Name)
	fmt.Println("isLocalJsMap", isLocalJsMap)
	idxCgEnable := c.String(RpcnodeIdxChangeFlag.Name)
	if idxCgEnable == DISABLE {
		committeeLen = CalculateCommitteeLen(isLocalJsMap)
		if committeeLen <= MINNODES {
			return errors.New("committeeLen is too small")
		}
	} else {
		committeeLen = c.Int(RpcCnodeNumFlag.Name)
	}
	fmt.Println("committeeLen", committeeLen)
	leaderIndex := c.Int(RpcLeaderIndexFlag.Name)
	genJsProcess(c, committeeLen, isLocalJsMap, uint16(leaderIndex))
	return nil
}

func minersStart(c *cli.Context) error {
	//manualReconfigStop(c)
	println("minersStart")
	gPort, _, mPassWord, _, _, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		println("isLocal", isLocal)
		return err
	}
	println("minersStart gPort", gPort)
	rString := GNODEDES
	mRole := c.String(RpcRoleFlag.Name)
	if mRole == "" {
		mRole = GNODE
		rString = GNODEDES
	}

	if mRole == CNODE {
		rString = CNODEDES
	} else if mRole == ALLNODES {
		rString = ALLNODESDES
	}

	if rString != ALLNODESDES {
		sendToNodesMinerFilter(c, rString, MINERSTART, mPassWord, isLocal, gIndex)
	} else {
		sendToNodesMinerFilter(c, GNODEDES, MINERSTART, mPassWord, isLocal, gIndex)
		sendToNodesMinerFilter(c, CNODEDES, MINERSTART, mPassWord, isLocal, gIndex)
	}
	//minersStatus(c)
	return nil
}

func manualReconfigStart(c *cli.Context) error {
	if err := minersStop(c); err != nil {
		println(err)
		return err
	} else {
		fmt.Println("")
		println("All nodes have been Suspended complete!" +
			"<<<So will send view change genesis file to the all nodes next step!>>>\r\n")

	}
	methodName := MANUALRECONFIGSTART
	_, _, mPassWord, _, _, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	rString := GNODEDES
	mRole := c.String(RpcRoleFlag.Name)
	if mRole == "" {
		mRole = GNODE
		rString = GNODEDES
	}

	if mRole == CNODE {
		rString = CNODEDES
	} else if mRole == ALLNODES {
		rString = ALLNODESDES
	}

	if rString != ALLNODESDES {
		sendToNodesMinerFilter(c, rString, methodName, mPassWord, isLocal, gIndex)
	} else {
		sendToNodesMinerFilter(c, CNODEDES, methodName, mPassWord, isLocal, gIndex)
		sendToNodesMinerFilter(c, GNODEDES, methodName, mPassWord, isLocal, gIndex)
	}
	//minersStatus(c)
	return nil
}

func manualReconfigStop(c *cli.Context) error {
	methodName := MANUALRECONFIGSTOP
	FullResponseCount = 0
	StoppedCount = 0
	_, _, _, _, _, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	mRole := c.String(RpcRoleFlag.Name)
	if mRole == "" {
		mRole = GNODE
	}
	rString := GNODEDES
	if mRole == CNODE {
		rString = CNODEDES
	} else if mRole == ALLNODES {
		rString = ALLNODESDES
	}
	if rString != ALLNODESDES {
		sendToNodesMinerFilter(c, rString, methodName, "", isLocal, gIndex)
	} else {
		sendToNodesMinerFilter(c, GNODEDES, methodName, "", isLocal, gIndex)
		sendToNodesMinerFilter(c, CNODEDES, methodName, "", isLocal, gIndex)
	}

	//minersStatus(c)
	//if StoppedCount < FullResponseCount {
	//	return errors.New("stop has not fully completed ")
	//}
	return nil
}

func minersStop(c *cli.Context) error {
	FullResponseCount = 0
	StoppedCount = 0
	_, _, _, _, _, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	methodName := MINERSTOP
	mRole := c.String(RpcRoleFlag.Name)
	if mRole == "" {
		mRole = GNODE
	}
	rString := GNODEDES
	if mRole == CNODE {
		rString = CNODEDES
	} else if mRole == ALLNODES {
		rString = ALLNODESDES
	}
	if rString != ALLNODESDES {
		sendToNodesMinerFilter(c, rString, methodName, "", isLocal, gIndex)
	} else {
		sendToNodesMinerFilter(c, GNODEDES, methodName, "", isLocal, gIndex)
		sendToNodesMinerFilter(c, CNODEDES, methodName, "", isLocal, gIndex)
	}

	minersStatus(c)
	if StoppedCount < FullResponseCount {
		return errors.New("stop has not fully completed ")
	}
	return nil
}
func senToSingleNodeMiner(c *cli.Context, filterkeyname, methodName, password string, isLocal bool, idex int) error {
	i := idex //single
	dString, err := getNodeValue(strconv.Itoa(i), DES, isLocal)
	//println(" senToSingleNodeMiner DES",dString)
	if err != nil {
		//	println("err",err)
		return err
	}

	if strings.Contains(dString, filterkeyname) == true {
		aString, err := getNodeValue(strconv.Itoa(i), URL, isLocal)
		//println(" senToSingleNodeMiner URL",dString)
		if err != nil {

			return err
		}

		if strings.Compare(methodName, MINERSTART) == 0 || strings.Compare(methodName, MANUALRECONFIGSTART) == 0 {
			cString, err := getNodeValue(strconv.Itoa(i), COINBASE, isLocal)
			if err != nil {

				return err
			}
			println("coinBase", cString)
			sendPost(aString, methodName, 1, cString, password)
		} else if strings.Compare(methodName, MINERSTOP) == 0 || strings.Compare(methodName, MANUALRECONFIGSTOP) == 0 {
			sendPost(aString, methodName, nil)
		}

	}
	return nil
}
func sendToNodesMinerFilter(c *cli.Context, filterkeyname, methodName, password string, isLocal bool, idex int) error {
	//fmt.Println("sendToNodesMinerFilter")
	if idex < 0 { //all
		//	fmt.Println("sendToNodesMinerFilter all")

		LeaderIndex = 0
		minersStatus(c)
		if LeaderIndex > 0 {
			senToSingleNodeMiner(c, filterkeyname, methodName, password, isLocal, LeaderIndex)
		}
		i := 0
		for {
			if err := senToSingleNodeMiner(c, filterkeyname, methodName, password, isLocal, i); err != nil {
				break
			}
			i++
		}
		//if strings.Contains(filterkeyname, CNODEDES) {
		//	senToSingleNodeMiner(filterkeyname, methodName, password, isLocal, 0)
		//}
	} else {
		senToSingleNodeMiner(c, filterkeyname, methodName, password, isLocal, idex)
	}
	return nil
}

func personalUnlockAll(c *cli.Context) error {
	_, sIpString, sPassword, _, _, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	nodeIndex := 0
	if gIndex > 0 {
		nodeIndex = gIndex
	}
	if sIpString == "" {

		aString, err := getNodeValue(strconv.Itoa(nodeIndex), URL, isLocal)
		if err != nil {
			return err
		}
		sendPost(aString, UNLOCKALL, sPassword)

	} else {
		return postMethod(c, UNLOCKALL)

	}
	return nil
}

func autoTransaction(c *cli.Context) error {

	_, sIpString, _, iEnable, iTime, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	nodeIndex := 0
	if gIndex >= 0 {
		nodeIndex = gIndex
	}

	if sIpString == "" || isLocal == true {
		fmt.Println("autoTransaction nodeIndex", nodeIndex)
		aString, err := getNodeValue(strconv.Itoa(nodeIndex), URL, isLocal)
		if err != nil {
			return err
		}

		if iEnable == 1 {
			tPassWord := c.String(RpcPasswdFlag.Name)
			if tPassWord == "" {

				tPassWord = DFPASSWD
			}
			sendPost(aString, UNLOCKALL, tPassWord)
			time.Sleep(5000 * time.Millisecond)
		}
		sendPost(aString, AUTOTRANS, iEnable, iTime)
	} else {
		if iEnable == 1 {
			if err := postMethod(c, UNLOCKALL); err != nil {
				return err
			}
		}
		return postMethod(c, AUTOTRANS, iEnable, iTime)
	}
	return nil
}
func getCommitteeMemberIndex(c *cli.Context) error {
	gIpString := c.String(RpcIpFlag.Name)
	fmt.Println("gIpString", gIpString)
	var err error
	var curCommitteeLocateIndex int
	var des string
	if des, curCommitteeLocateIndex, err = ipFilterFindTargetValue(URL, gIpString, DES); err != nil {

		return err
	}

	fmt.Println("curCommitteeLocateIndex", curCommitteeLocateIndex)
	fmt.Println("des", des)
	return nil
}

func getCommitteeLen(c *cli.Context) error {
	PreFixStr = c.String(PreFixNameFlag.Name)
	isLocalJsMap := c.Int(RpcJsLocalFlag.Name)
	fmt.Println("isLocalJsMap", isLocalJsMap)
	committeeLen := CalculateCommitteeLen(isLocalJsMap)
	fmt.Println("committeeLen", committeeLen)

	return nil
}

func rosterConfig(c *cli.Context) error {
	isLocalJsMap := c.Int(RpcJsLocalFlag.Name)
	fmt.Println("isLocalJsMap", isLocalJsMap)
	//committeeLen := c.Int(RpcCnodeNumFlag.Name)
	committeeLen := CalculateCommitteeLen(isLocalJsMap)
	fmt.Println("committeeLen", committeeLen)
	if committeeLen <= MINNODES {
		return errors.New("committeeLen is too small")
	}
	leaderIndex := c.Int(RpcLeaderIndexFlag.Name)
	//minersStatus(c)
	//if committeeNum > 0 {
	//	if leaderIndex > 0 {
	//		LeaderIndex = leaderIndex
	//	} else {
	//		if LeaderIndex > 0 {
	//			leaderIndex = int(LeaderIndex)
	//		} else {
	//			rlog.Info("get LeaderIndex error")
	//			return errors.New("get LeaderIndex error")
	//		}
	//	}
	//	genJsProcess(committeeNum, isLocalJsMap, uint16(leaderIndex))
	//}
	genJsProcess(c, committeeLen, isLocalJsMap, uint16(leaderIndex))
	fmt.Println("getJsMapFileBytes")
	jsMapBuf := getJsMapFileBytes(isLocalJsMap)
	manualReconfigStart(c)
	return postMethod(c, ROSTERCONFIG, jsMapBuf)

}

func postToAll(methodName string, isLocal bool, idex int, params ...interface{}) error {

	if idex < 0 {
		i := 0
		for {

			aString, err := getNodeValue(strconv.Itoa(i), URL, isLocal)
			if err != nil {

				return err
			}
			sendPost(aString, methodName, params)
			i++
		}
	} else {
		i := idex
		aString, err := getNodeValue(strconv.Itoa(i), URL, isLocal)
		if err != nil {

			return err
		}

		sendPost(aString, methodName, params)

	}
	return nil
}

func ipFilterFindTargetValue(fromKeyName, fromKeyValue, toKeyName string) (string, int, error) {
	i := 0
	isLocal := true
	if fromKeyValue != LOCALIP {
		isLocal = false
	}
	for {

		vSrcString, err := getNodeValue(strconv.Itoa(i), fromKeyName, isLocal)
		if err != nil {
			return "", i, err
		}
		if fromKeyValue != "1" && fromKeyValue != " " {
			if strings.Contains(vSrcString, fromKeyValue) == true {
				//fmt.Println(vSrcString)
				fmt.Println(fromKeyValue)
				vDestString, err := getNodeValue(strconv.Itoa(i), toKeyName, isLocal)
				if err != nil {
					return "", i, err
				}
				return vDestString, i, nil
			}
		}
		i++
		fmt.Println("i", i)
	}
	return "", i, nil

}

var FullResponseCount uint16
var StoppedCount uint16
var CommitteeMemberCount uint16

var LeaderIndex int

func sendPost(targetUrl string, methodName string, params ...interface{}) {
	fmt.Println("sendPost methodName", methodName)
	req := curl.NewRequest()
	rpcHeaders := map[string]string{
		"Content-Type": "application/json",
	}

	postData := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  methodName,
		"params":  params,
		"id":      67,
	}

	resp, err := req.
		SetUrl(targetUrl).
		SetHeaders(rpcHeaders).
		SetPostData(postData).
		Post()

	if err != nil {
		fmt.Println(err)
	} else {
		if resp.IsOk() {
			if methodName == MINERSTATUS {
				FullResponseCount++
				res, err := simplejson.NewJson([]byte(resp.Body))
				if err != nil {
					fmt.Printf("NewJson \n", err)
					return
				}
				var resultString string
				if resultString, err = res.Get("result").String(); err != nil {
					return
				}
				fmt.Println("result", resultString)
				if strings.Contains(resultString, "Stopped") {
					StoppedCount++
				}
				if strings.Contains(resultString, LeaderStatus) {
					LeaderIndex, _ = GetIndexAccordURL(targetUrl)
					//fmt.Println("found leader:", targetUrl, "\nmsg:", resp.Body)
					fmt.Println("LeaderIndex", LeaderIndex)
				}
				if strings.Contains(resultString, MemberStatus) {
					CommitteeMemberCount += 1
					//fmt.Println("found leader:", targetUrl, "\nmsg:", resp.Body)
					fmt.Println("CommitteeMemberCount", CommitteeMemberCount)
				}

			}
			fmt.Println("SUCCESS! response from:", targetUrl, "\nmsg:", resp.Body)

		} else {
			fmt.Println(resp.Raw)
		}
	}
}

func LoadFile(filename string) ([]byte, error) {

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

func countLines(fileName string, counts map[int]string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return err
	}

	buf := bufio.NewReader(f)
	i := 0
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		counts[i] = line
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		i++
	}
	return nil
}

func Print(line string) {
	fmt.Println(line)
}

func WriteFile(filename string, data []byte) {
	fp, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer fp.Close()
	_, err = fp.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}
func StringTrimInsert(srcStr, trimStr, insertStr string) string {
	//println("srcStr", srcStr)
	//println("trimStr", trimStr)
	trimLeftString := strings.TrimSuffix(srcStr, trimStr)
	//println("trimLeftString", trimLeftString)
	destStr := trimLeftString + insertStr + trimStr
	//println("destStr", destStr)
	return destStr
}
func CalculateCommitteeLen(isLocalJsMap int) int {
	jsonFilePathStr := genesis
	if isLocalJsMap == 1 {
		jsonFilePathStr = StringTrimInsert(jsonFilePathStr, ".json", "Local")
	}
	//println("jsonFilePathStr", jsonFilePathStr)
	jsonFile, err := LoadFile(GetFilePath(jsonFilePathStr))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return 0
	}
	res, err := simplejson.NewJson(jsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return 0
	}
	i := 0
	for {
		aString, err := res.Get("config").Get("committee").Get(strconv.Itoa(int(i))).Get(URL).String()
		if err != nil {
			return i
		}
		if aString == "" {
			return i + 1
		}
		//fmt.Println("iLen",i)
		i++
	}
	return i + 1

}

func getJsMapFileBytes(isLocalJsMap int) string {
	jsonFilePathStr := rpcjsonfile
	if isLocalJsMap == 1 {
		jsonFilePathStr = PreFixStr + jsonFilePathStr
	}
	println("jsonFilePathStr", jsonFilePathStr)
	jsonFile, err := LoadFile(GetFilePath(jsonFilePathStr))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return ""
	}
	//fmt.Println(string(jsonFile))
	return string(jsonFile)
}

func ReadLineFile(fileName string) {
	if file, err := os.Open(fileName); err != nil {
		panic(err)
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}
}

func genJsProcess(c *cli.Context, committeNum int, isLocalJsMap int, leaderIndex uint16) (string, error) {
	nodeIdxChangeFlag := c.Int(RpcnodeIdxChangeFlag.Name)
	startIndex := c.Int(StartIndexFlag.Name)
	//SortEnable:=c.String(SortEnableFlag.Name)
	log.Println("genJsProcess committeNum", committeNum)
	preFixName := ""
	accountPreFixName := ""
	if isLocalJsMap == 1 {
		preFixName = PreFixStr
		accountPreFixName = PreFixStr + "Chaindb/"
	} else {
		accountPreFixName = "chaindbtest/"
	}

	accountsFile, err := LoadFile(GetFilePath(accountPreFixName + accountsfile))
	if err != nil {
		fmt.Printf("accountsFile \n", err)
		return "", err
	}

	accountsFileStr := string(accountsFile)

	sourceGenesisJsonFile, err := LoadFile(GetFilePath(genesis))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return "", err
	}

	sourceGenesiJson, err := simplejson.NewJson(sourceGenesisJsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return "", err
	}

	sourceGenesisCommonJsonFile, err := LoadFile(GetFilePath(genesis))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return "", err
	}

	sourceGenesiCommonJson, err := simplejson.NewJson(sourceGenesisCommonJsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return "", err
	}

	sourceRpcJsonFile, err := LoadFile(GetFilePath(rpcjsonfile))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return "", err
	}

	sourceRpcJson, err := simplejson.NewJson(sourceRpcJsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return "", err
	}
	//fmt.Println("res",res)
	//jsonByte, err := json.MarshalIndent(res, "", "  ")
	//if err!=nil{
	//
	//}
	////fmt.Println("jsonByte",jsonByte)
	//WriteFile(rpcjsonfile,jsonByte)

	ipFileLineStrMap := make(map[int]string)

	f, err := os.Open(GetFilePath(preFixName + hostsfile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "hostsfile: %v\n", err)
		return "", err
	}
	f.Close()

	countLines(GetFilePath(preFixName+hostsfile), ipFileLineStrMap)

	i := 0
	endIndex := startIndex + committeNum
	log.Println("i", i)
	log.Println("endIndex", endIndex)
	accountIdxNum := 0
	rpcNodes := RpcNodes{make(map[string]rpcHeader)}
	err = json.Unmarshal([]byte(sourceRpcJsonFile), rpcNodes.nodes)
	if err != nil {
	}
	genesisNodes := genesisNodes{make(map[string]genesisHeader)}
	err = json.Unmarshal([]byte(sourceGenesisJsonFile), genesisNodes.nodes)
	if err != nil {
	}

	genesisCommonNodes := genesisCommonNodes{make(map[string]genesisCommonHeader)}
	err = json.Unmarshal([]byte(sourceGenesisCommonJsonFile), genesisCommonNodes.nodes)
	if err != nil {
	}
	//fmt.Println("rpcNodes.nodes", rpcNodes.nodes)
	allocCoinNodes := AllocCoin{make(map[string]Coin)}
	//err = json.Unmarshal([]byte(jsonFile), genesisNodes)
	//if err !=nil{return err}
	var hostsRawStr, ipHostStr, accountIdxNumStr string
	//PubKey, PriKey := types.NewEpochKeyPair()
	//fmt.Println("PubKey", PubKey)
	//fmt.Println("PriKey", PriKey)
	//epochKeyPair := EpochKeyPair{EpochPubKey: hexutil.Encode(PubKey), EpochPriKey: hexutil.Encode(PriKey)}
	//fmt.Println("epochKeyPair PubKey ", epochKeyPair.EpochPubKey)
	//fmt.Println("epochKeyPair PriKey ", epochKeyPair.EpochPriKey)

	rpcNodesJson := sourceRpcJson
	genesisNodesJson := sourceGenesiJson
	genesisCnNodesJson := sourceGenesiCommonJson
	allocCoinNodeJson := sourceGenesiJson
	var rpcNodesOutPut []byte
	for {
		accountIdxNum = i
		iStr := strconv.Itoa(i)
		accountIdxNumStr = strconv.Itoa(accountIdxNum)
		hostsRawStr = ipFileLineStrMap[i]
		if net.ParseIP(hostsRawStr) != nil {
			//fmt.Println("isLocalJsMap", isLocalJsMap)
			//fmt.Println("hostsRawStr", hostsRawStr)
			//fullStopIdx := strings.LastIndex(hostsRawStr, ".")
			//if fullStopIdx < 0 {
			//	goto End
			//}
			//hostLineEndLocationIdx := metrics.UnicodeIndex(hostsRawStr, " ")
			//fmt.Println("hostLineEndLocationIdx:", hostLineEndLocationIdx)
			//if hostLineEndLocationIdx < 0 {
			//	fmt.Println("hostLineEndLocationIdx < 0 ")
			//	goto End
			//}

			//ipHostStr = metrics.SubString(hostsRawStr, 0, hostLineEndLocationIdx)
			ipHostStr = hostsRawStr
			if nodeIdxChangeFlag == 1 {
				//accountIdxNumStr = metrics.SubString(hostsRawStr, hostLineEndLocationIdx+1, 5)
				accountIdxNumStr = iStr
				if accountIdxNum, err = strconv.Atoi(accountIdxNumStr); err != nil {
					fmt.Errorf("get idxChangeOnetPortNum ", err)
				}
			}

			accountLineEndLocationIdx := metrics.UnicodeIndex(accountsFileStr, ACCOUNTPREFIX+iStr)
			nodeStr := "Node " + strconv.Itoa(i+1) + " accounts:"
			accountLocation := strings.Index(accountsFileStr, nodeStr)
			//fmt.Println("accountLocation", accountLocation)
			//fmt.Println("nodeStr:", nodeStr)
			accountLineEndLocationIdx = accountLocation + 25 //Experience point

			iStrLen := len(iStr)
			if iStr == "9" {
				accountLineEndLocationIdx += 1
			}

			sCoinBase := metrics.SubString(accountsFileStr, accountLineEndLocationIdx+4+iStrLen-1, common.AddressLength*2)
			sPublic := metrics.SubString(accountsFileStr, accountLineEndLocationIdx+4+common.AddressLength*2+iStrLen+1, BlsPubkeyLength*2)
			var sCoinBaseSub string
			sCoinBaseSub = metrics.SubString(accountsFileStr, accountLineEndLocationIdx+4+common.AddressLength*2+iStrLen+1+BlsPubkeyLength*2+13, common.AddressLength*2)
			fmt.Println("sCoinBaseSub:", sCoinBaseSub)

			//fmt.Println("idx:", i)
			//fmt.Println("accountIdxNum:", accountIdxNum)
			//fmt.Println("ipHostStr:", ipHostStr)
			//fmt.Println("sCoinBase:", sCoinBase)
			//fmt.Println("sPublic:", sPublic)

			sDescription := CNODEDES
			desIndex := i
			if nodeIdxChangeFlag == 1 {
				desIndex = accountIdxNum
			}
			//if SortEnable==DISABLE{}
			if desIndex < endIndex {
				sDescription = CNODEDES + strconv.Itoa(desIndex+startIndex)
			} else {
				sDescription = GNODEDES + strconv.Itoa(desIndex+startIndex-endIndex)
				//fmt.Println(">=endIndex sDescription", sDescription)
			}
			//fmt.Println("accountIdxNum", accountIdxNum)
			var onetPortStr string
			if isLocalJsMap == 0 {
				onetPortStr = ":" + strconv.Itoa(DFONETPORT)
			} else {
				onetPortStr = ":" + strconv.Itoa(DFONETPORT+MULRADIX*(i+1))
			}

			ipHostStrAndPort := ipHostStr + onetPortStr
			var gsisCommonHdr genesisCommonHeader
			var rpcHdr rpcHeader
			var gsisHdr genesisHeader

			rpcHdr = rpcHeader{Address: ipHostStrAndPort, CoinBase: sCoinBase, Public: sPublic, Description: sDescription}
			gsisHdr = genesisHeader{Address: ipHostStrAndPort, Public: sPublic, CoinBase: sCoinBase}
			gsisCommonHdr = genesisCommonHeader{Public: sPublic, CoinBase: sCoinBase}
			rpcHeaderByte, err := json.MarshalIndent(rpcHdr, "", "  ")
			if err != nil {
				return "", err
			}
			var gsisHeaderByte []byte
			gsisHeaderByte, err = json.MarshalIndent(gsisHdr, "", "  ")
			if err != nil {
				return "", err
			}
			var gsisCommonHeaderByte []byte
			gsisCommonHeaderByte, err = json.MarshalIndent(gsisCommonHdr, "", "  ")
			if err != nil {
				return "", err
			}
			json.Unmarshal([]byte(rpcHeaderByte), rpcHdr)
			json.Unmarshal([]byte(gsisHeaderByte), gsisHdr)
			json.Unmarshal([]byte(gsisCommonHeaderByte), gsisCommonHdr)
			desIndexStr := strconv.Itoa(desIndex + startIndex)
			fmt.Println("desIndex", desIndex)
			rpcNodes.nodes[desIndexStr] = rpcHdr
			coin := Coin{Balance: ALLOCCOIN}
			if i == 1 || i == 2 {
				allocCoinNodes.allocCoinNodes[sCoinBase] = coin
				allocCoinNodes.allocCoinNodes[sCoinBaseSub] = coin
			}
			if desIndex < endIndex {
				genesisNodes.nodes[desIndexStr] = gsisHdr
				genesisCommonNodes.nodes[desIndexStr] = gsisCommonHdr

			}
			fmt.Println("i", i)
			i++

		} else {
			goto End
		}
	}
End:
	fmt.Println("preFixName", preFixName)
	allocCoinNodeJson.SetPath([]string{"alloc"}, allocCoinNodes.allocCoinNodes)
	allocCoinNodeOutPut, err := json.MarshalIndent(allocCoinNodeJson, "", "  ")
	if err != nil {
		return "", err
	}
	{
		//rpcnodesjs
		//rpcNodesJson.SetPath([]string{"epochPubKey"}, epochKeyPair.EpochPubKey)
		//rpcNodesJson.SetPath([]string{"epochPriKey"}, epochKeyPair.EpochPriKey)
		rpcNodesJson.SetPath([]string{"config", "committee"}, rpcNodes.nodes)

		rpcNodesOutPut, err = json.MarshalIndent(rpcNodesJson, "", "  ")
		if err != nil {
			return "", err
		}

		fmt.Println("rpcNodesOutPut:", string(rpcNodesOutPut))
		WriteFile(GetFilePath(preFixName+rpcjsonfile), rpcNodesOutPut)
		WriteFile(GetFilePath(preFixName+rpcjsonfile), allocCoinNodeOutPut)
	}

	{
		//genesisnodesjs
		//genesisNodesJson.SetPath([]string{"epochPubKey"}, epochKeyPair.EpochPubKey)
		//genesisNodesJson.SetPath([]string{"epochPriKey"}, epochKeyPair.EpochPriKey)
		genesisNodesJson.SetPath([]string{"config", "committee"}, genesisNodes.nodes)
		gsisOutPut, err := json.MarshalIndent(genesisNodesJson, "", "  ")
		if err != nil {
			return "", err
		}
		fmt.Println("gsisOutPut:", string(gsisOutPut))
		WriteFile(GetFilePath(preFixName+genesisoutputfile), gsisOutPut)
		WriteFile(GetFilePath(preFixName+genesisoutputfile), allocCoinNodeOutPut)
	}

	//genesiscommonnodesjs
	if isLocalJsMap == 0 {

		genesisCnNodesJson.SetPath([]string{"config", "committee"}, genesisCommonNodes.nodes)
		gsisCnOutPut, err := json.MarshalIndent(genesisCnNodesJson, "", "  ")
		if err != nil {
			return "", err
		}
		fmt.Println("genesisCnNodesJson:", string(gsisCnOutPut))
		//err = os.Remove(preFixName+genesiscommonoutputfile)
		//if err != nil {
		//} else {
		//	fmt.Println("delete genesiscommonoutput.json fail ")
		//	return "", err
		//}
		//WriteFile(GetFilePath(preFixName+genesiscommonoutputfile), gsisCnOutPut)
		//WriteFile(GetFilePath(preFixName+genesiscommonoutputfile), allocCoinNodeOutPut)
	}
	return string(rpcNodesOutPut), nil
}

func GetRpcNodesLen(isLocalJsMap bool) (int, error) {
	var i int
	prefixStr := ""
	if isLocalJsMap {
		prefixStr = PreFixStr
	}
	jsonFile, err := LoadFile(GetFilePath(prefixStr + rpcjsonfile))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return 0, err
	}
	res, err := simplejson.NewJson(jsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return 0, err
	}
	for {
		aString, err := res.Get("config").Get("committee").Get(strconv.Itoa(int(i))).Get(URL).String()
		if err != nil {
			return i, err
		}
		if aString == "" {
			return i, nil
		}
		i++
	}
}
func GetIndexAccordURL(url string) (int, error) {
	var i int
	prefixStr := ""
	if strings.Contains(url, "127.0.0.1") {
		prefixStr = PreFixStr
	}
	jsonFile, err := LoadFile(GetFilePath(prefixStr + rpcjsonfile))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return -1, err
	}
	res, err := simplejson.NewJson(jsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return -1, err
	}
	for {
		aString, err := res.Get("config").Get("committee").Get(strconv.Itoa(int(i))).Get(URL).String()
		if err != nil {
			return -1, err
		}
		//aString = strings.TrimLeft(aString, ": ")
		//aString = strings.Replace(aString, "tcp", "http", -1)
		//println("url", url)
		//println("before processing, aString",aString)
		var curOnetPortStr, targetPortStr string
		if prefixStr == PreFixStr {
			curOnetPortStr = strconv.Itoa(DFONETPORT + int((i+1)*2))
			targetPortStr = strconv.Itoa(RpcPortValue + int((i)*2))
		} else {
			curOnetPortStr = strconv.Itoa(DFONETPORT)
			targetPortStr = strconv.Itoa(RpcPortValue)
		}
		//println("GetIndexAccordURL curOnetPortStr", curOnetPortStr)
		//println("GetIndexAccordURL targetPortStr", targetPortStr)
		aString = strings.Replace(aString, curOnetPortStr, targetPortStr, -1)
		//println("after processing, aString", aString)
		if strings.Compare(aString, url) == 0 {
			Description, err := res.Get("config").Get("committee").Get(strconv.Itoa(int(i))).Get(DES).String()
			if err != nil {
				return -1, err
			}
			fmt.Println("Description", Description)
			i, err := strconv.Atoi(strings.TrimLeft(Description, CNODEDES))
			if err != nil {
				return -1, err
			}
			println("I have found leader,Leader idx=", i)
			return i, nil
		}
		i++
	}
	println("I have not found leader")
	return -1, nil
}

func setSingleRpcNodeAccordHostNameMapAndCurrentRpcFile(ipStr, IndexStr string, committeNum int, isLocal bool) rpcHeader {
	var err error
	var curCommitteeLocateIndex int
	//fmt.Println("ipStr",ipStr)
	if _, curCommitteeLocateIndex, _ = ipFilterFindTargetValue(URL, ipStr, DES); err != nil {
		//」fmt.Println("setSingleRpcNodeAccordHostNameMapAndCurrentRpcFile err",err)
		//fmt.Println("curCommitteeLocateIndex",curCommitteeLocateIndex)
		//return rpcHeader{}
	}

	curCommitteeLocateIndexStr := strconv.Itoa(curCommitteeLocateIndex)

	var rpcHdr rpcHeader
	if rpcHdr, err = getRpcHeaderAccordToIndexString(curCommitteeLocateIndexStr, isLocal); err != nil {
		fmt.Println("err", err)
	}
	//fmt.Println("curCommitteeLocateIndexStr",curCommitteeLocateIndexStr)
	fmt.Println("rpcHdr", rpcHdr)
	sDescription := CNODEDES
	index, _ := strconv.Atoi(IndexStr)
	var onetPortStr string
	if !isLocal {
		onetPortStr = ":" + strconv.Itoa(DFONETPORT)
	} else {
		onetPortStr = ":" + strconv.Itoa(DFONETPORT+MULRADIX*(index+1))
	}
	ipHostStrAndPort := ipStr + onetPortStr
	if index < committeNum {
		sDescription = CNODEDES + strconv.Itoa(index)
	} else {
		sDescription = GNODEDES + strconv.Itoa(index-committeNum)
		//fmt.Println(">=committeNum sDescription", sDescription)
	}
	rpcHdr.Description = sDescription
	rpcHdr.Address = ipHostStrAndPort
	return rpcHdr
}

func getRpcHeaderAccordToIndexString(indexStr string, isLocal bool) (rpcHeader, error) {

	sCoinBase, _ := getNodeValue(indexStr, COINBASE, isLocal)
	sCoinBase = strings.TrimLeft(sCoinBase, "0x")
	//fmt.Println("sCoinBase",sCoinBase)
	sPublicKey, _ := getNodeValue(indexStr, PUBLIC, isLocal)

	sDes, _ := getNodeValue(indexStr, DES, isLocal)
	sURL, _ := getNodeValue(indexStr, URL, isLocal)
	//sURL = strings.TrimLeft(sURL, ": ")
	//sURL = strings.Replace(sURL, "http", "tcp", -1)
	println("sURL", sURL)
	//sSuite, _ := getNodeValue(indexStr, SUITE, isLocal)
	fmt.Println("sCoinBase", sCoinBase)
	fmt.Println("sPublicKey", sPublicKey)
	rpcHdr := rpcHeader{Address: sURL, CoinBase: sCoinBase, Public: sPublicKey, Description: sDes}

	return rpcHdr, nil
}
func getNodeValue(nodekey, propertykey string, isLocal bool) (string, error) {

	prefixStr := ""
	if isLocal {
		prefixStr = PreFixStr
		//fmt.Println("getNodeValue isLocal")
	}
	filePathStr := prefixStr + rpcjsonfile
	//fmt.Println("nodekey", nodekey)
	//fmt.Println("propertykey", propertykey)
	//fmt.Println("filePathStr", filePathStr)

	jsonFile, err := LoadFile(GetFilePath(filePathStr))
	if err != nil {
		fmt.Printf("LoadFile %v\n", err)
		return "", err
	}
	res, err := simplejson.NewJson(jsonFile)
	if err != nil {
		fmt.Printf("NewJson %v\n", err)
		return "", err
	}
	aString, err := res.Get("config").Get("committee").Get(nodekey).Get(propertykey).String()
	if err != nil {

		return "", err
	}
	//aString = strings.TrimLeft(aString, ":")
	//println("aString", aString)
	switch propertykey {
	case URL:
		//aString = strings.Replace(aString, "tcp", "http", -1)
		aString = "http://" + aString
		//println("aString URL", aString)
		curOnetPort := DFONETPORT
		curOnetPortStr := strconv.Itoa(DFONETPORT)

		targetPortStr := strconv.Itoa(RpcPortValue)
		if prefixStr == PreFixStr {
			curOnetPortLineEndIdx := strings.LastIndex(aString, ":")
			curOnetPortStr = metrics.SubString(aString, curOnetPortLineEndIdx+1, 5)
			if curOnetPort, err = strconv.Atoi(curOnetPortStr); err != nil {
				println(err)
				return "", err
			}
			targetPortStr = strconv.Itoa((int(curOnetPort-DFONETPORT)/2-1)*2 + RpcPortValue)
			//println("curOnetPort" ,curOnetPort)
			//println("targetPortStr" ,targetPortStr)
		} else {
			targetPortStr = strconv.Itoa(RpcPortValue)
		}
		//println("getNodeValue curOnetPortStr",curOnetPortStr)
		//println("getNodeValue targetPortStr",targetPortStr)

		aString = strings.Replace(aString, curOnetPortStr, targetPortStr, -1)
		//println("after aString",aString)
		return aString, nil
	case COINBASE:

		return "0x" + aString, nil
	case PUBLIC, DES:
		return aString, nil

	default:
		return "", errors.New("dost not exist key")

	}
}

var RpcPortValue int

func getPortIpsPassword(c *cli.Context) (int, string, string, int, int, string, int) {
	RpcPortValue = c.Int(RpcPortFlag.Name)
	if RpcPortValue == 0 {
		RpcPortValue = DFRPCPORT
	}
	gIpString := c.String(RpcIpFlag.Name)

	gPassWord := c.String(RpcPasswdFlag.Name)
	if gPassWord == "" {
		gPassWord = DFPASSWD
	}
	gEnable := c.Int(RpcEnableFlag.Name)

	gTime := c.Int(RpcTimeFlag.Name)
	if gTime == 0 {

		gTime = DFTIME
	}
	gLocal := c.String(RpcJsLocalFlag.Name)

	gIndex := c.Int(RpcNodeIndexFlag.Name)
	PreFixStr = c.String(PreFixNameFlag.Name)

	return RpcPortValue, gIpString, gPassWord, gEnable, gTime, gLocal, gIndex
}

func postMethod(c *cli.Context, methodname string, params ...interface{}) error {
	fmt.Println("postMethod name:", methodname)
	sPort, sIpString, sPassword, iEnable, iTime, gLocal, gIndex := getPortIpsPassword(c)
	var isLocal bool
	var err error
	if isLocal, err = strconv.ParseBool(gLocal); err != nil {
		return err
	}
	if sIpString == "" || isLocal == true {

		err := postToAll(methodname, isLocal, gIndex, params)
		if err != nil {

			return err
		}
	} else {

		mIps := strings.Split(sIpString, ",")

		for _, ipString := range mIps {
			urlstr := "http://" + ipString + ":" + strconv.Itoa(sPort)

			switch methodname {
			case MINERSTART, MANUALRECONFIGSTART:
				cString, _, err := ipFilterFindTargetValue(URL, ipString, COINBASE)
				//coinAddress:=common.BytesToAddress([]byte(cString))
				println("coinbase", cString)
				if err == nil && cString != "" {
					sendPost(urlstr, methodname, 1, cString, sPassword)
				}

			case MINERSTOP, MANUALRECONFIGSTOP, MINERSTATUS, ACCOUNTS, KEYBLKNUM, TXBLKNUM, PEERCOUNT, PEERS, TXPOOLSATUS, TXPOOLINSPECT:
				sendPost(urlstr, methodname, nil)
			case GETBALANCE:
				txBnr := c.String(RpcTxBnrFlag.Name)
				//i := 0
				//for {
				//
				//	cString, err := getNodeValue(strconv.Itoa(i), COINBASE)
				//	if err != nil {
				//
				//		goto End
				//	}
				//	fmt.Println("coinbase",cString)
				//	sendPost(urlstr, methodname,cString,txBnr)
				//
				//	i++
				//}
				//
				//
				//goto End
				coinBase := c.String(RpcCoinBaseFlag.Name)
				if coinBase == "" {
					cString, err := getNodeValue(DFIDX, COINBASE, isLocal)
					if err != nil {

						goto End
					}
					coinBase = cString
				}
				if strings.Contains(coinBase, "0x") == false {
					coinBase = "0x" + coinBase
				}
				sendPost(urlstr, methodname, coinBase, txBnr)

			case UNLOCKALL:
				sendPost(urlstr, methodname, sPassword)

			case AUTOTRANS:
				sendPost(urlstr, methodname, iEnable, iTime)
			case SENDTRANS:
				fromCoinBase := c.String(RpcFromFlag.Name)
				if strings.Contains(fromCoinBase, "0x") == false {
					fromCoinBase = "0x" + fromCoinBase
				}
				toCoinBase := c.String(RpcToFlag.Name)
				if strings.Contains(toCoinBase, "0x") == false {
					toCoinBase = "0x" + toCoinBase
				}

				amountValue := c.String(RpcAmountFlag.Name)

				sendPost(urlstr, methodname, fromCoinBase, toCoinBase, amountValue)
			case ROSTERCONFIG:
				fmt.Println("RECONFIG methodname%x,%x", methodname, params)
				sendPost(urlstr, methodname, params)
			}

		}

	}
End:
	return nil
}
