#!/bin/bash

TOP_PID=$$
CYPHER="./build/bin/cypher"
GENESIS="./genesisLocal.json"
NODE_DIR="localChaindb"
#NODE_DIR="localChaindb"
NODES_MAX=100
NODES_NUM=0
ACCOUNTSLIST="$NODE_DIR/accounts.txt"
LOGLEVEL=6
# Commands
CLEANDB="cleandb"
INIT="init"
CLEAN="clean"
CLDBF="clnode"
APPEND="append"
CONSOLE="cs"
RESTART="csr"
ATTACH="attach"
STOP="stop"
NEWACCOUNT="newAccount"
LISTACCOUNT="listAccount"
IPENCDISVALUE=1
PRMV=1
EnableFlags="" #"--jvm --evm"

#LOCALIP="192.168.0.146"

localip=`ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"​`
LOCALIP=`echo $localip|awk '{print $1}'`
BOOTNODEIP="192.168.1.211"
BOOTNODE="cnode://6941c498a447e0f5ddbbb4b045cff0583bff20789ed6716de016a3eeefe385db7e9a0b61eeedeb40b371f6f1daec7eb0d0024d3e3d3aeabf6186f971ae8f5156@$BOOTNODEIP:30301"
NetWorkId=`less ${GENESIS} | awk -F "[:]" '/chainId/{print $2}'`
NetWorkId=`echo ${NetWorkId} | cut -d \, -f 1`

log()
{
    echo 1>&2 "$1"
}

die()
{
    log "$1"
    kill -s TERM $TOP_PID
}

die_usage()
{
    log "Usage: $0 [init|cleandb] <number_of_nodes>"
    log "    init: init nodes from genesis file"
    log "    clean: remove nodes database including keystore"
    log "    cleandb: remove nodes' database except keystore"
    log "    stop: kill node by specify its number"
    log "    <number_of_nodes>: number of nodes you want to run"
    die
}

init_node()
{
    log "Init nodes...."
      #cldbf
    for n in $( seq $NODES_NUM ); do
        mkdir -p "$NODE_DIR/$n"
        sudo rm -rf $NODE_DIR/$n/cypher $NODE_DIR/$n/cypher.ipc $HOME/*.log
        sleep .2
        $CYPHER $EnableFlags --datadir "$NODE_DIR/$n" init "$GENESIS"
    done
}

#
# List accounts for each nodes.
#
list_account()
{
    PASSWORD=`mktemp`
    echo '1' > $PASSWORD

    echo "" > "$ACCOUNTSLIST"
    for n in $( seq $NODES_NUM ); do
        printf "\n\nNode $n accounts:\n" >> "$ACCOUNTSLIST"
        $CYPHER account list $EnableFlags  --datadir "$NODE_DIR/$n" --password $PASSWORD >> "$ACCOUNTSLIST"
#        printf "$MSG" >> "$ACCOUNTSLIST"
    done

    rm -f $PASSWORD
    log "Check out $NODE_DIR/accounts.txt for accounts detail"
}


#
# Create 2 accounts for each nodes.
#
new_account()
{
    PASSWORD=`mktemp`
    echo '1' > $PASSWORD
    for n in $( seq $NODES_NUM ); do
        log "Create two accounts for node $n...."
        mkdir -p "$NODE_DIR/$n"
        $CYPHER account new $EnableFlags  --datadir "$NODE_DIR/$n" --password $PASSWORD
        $CYPHER account new $EnableFlags  --datadir "$NODE_DIR/$n" --password $PASSWORD
    done
    rm -f $PASSWORD

    list_account
}

#
# append_node: start additional nodes
# - argument 1: Nodes number already running
# - argument 2: additional nodes number to append
#
append_node()
{
    log "Append $NODES_NUM nodes...."
    for m in $( seq $NODES_NUM ); do
        n=$(($1 + m))
        #log "Node $n -onetport@$((7100 + 2 * $n)) - port@$((16000 + 2 * $n)) - rpcport@$((18000 + 2 * $n)) - rpc path: $NODE_DIR/$n/cypher.ipc"
        log "./build/bin/cypher attach $NODE_DIR/$n/cypher.ipc"
        # --ws  -wsaddr="0.0.0.0" --wsorigins "*"
        if [[ "$n" -eq 1 ]]; then
	$CYPHER  --onetport $((7100 + 2 * $n)) --nat=extip:$LOCALIP  --ws $EnableFlags  --powrangemode $PRMV --localtest $LOCALIP  -wsaddr="0.0.0.0" --wsorigins "*" --tps --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal,miner,txpool --port $((16000 + 2 * $n)) --rpcport $((18000 + 2 * $n)) --verbosity "$LOGLEVEL" --datadir "$NODE_DIR/$n" --networkid $NetWorkId --gcmode archive --bootnodes "$BOOTNODE" 2>"$NODE_DIR/$n/$n.log" &
        else
            $CYPHER  --onetport $((7100 + 2 * $n)) --tps $EnableFlags  --nat=extip:$LOCALIP --powrangemode $PRMV --localtest $LOCALIP  --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal,miner,txpool --port $((16000 + 2 * $n)) --rpcport $((18000 + 2 * $n)) --verbosity "$LOGLEVEL" --datadir "$NODE_DIR/$n" --networkid $NetWorkId --gcmode archive --bootnodes "$BOOTNODE" 2>"$NODE_DIR/$n/$n.log" &
        fi
    done

}

console_node()
{

    if [ ! -d "$NODE_DIR/$NODES_NUM/cypher.ipc" ]; then

     mkdir -p "$NODE_DIR/$NODES_NUM"
     $CYPHER $EnableFlags  --datadir "$NODE_DIR/$NODES_NUM" init "$GENESIS"
    fi

    log "console $NODES_NUM node...."
        n=$(($1 + $NODES_NUM))
        $CYPHER   --onetport $((7100 + 2 * $n)) --nat "none" --tps $EnableFlags --powrangemode $PRMV --localtest $LOCALIP --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal,miner,txpool --port $((16000 + 2 * $n)) --rpcport $((18000 + 2 * $n)) --verbosity "$LOGLEVEL" --datadir "$NODE_DIR/$NODES_NUM" --networkid $NetWorkId --gcmode archive --bootnodes "$BOOTNODE" console


}

attach_node()
{
       if [ ! -d "$NODE_DIR/$NODES_NUM/cypher.ipc" ]; then

        mkdir -p "$NODE_DIR/$NODES_NUM"
        $CYPHER $EnableFlags  --datadir "$NODE_DIR/$NODES_NUM" init "$GENESIS"
        log "sleep several seconds wait cypher.ipc"
        sleep 2
       fi

       log "attach $NODES_NUM node...."
        n=$(($1 + $NODES_NUM))
        log "Node $n -onetport@$((7100 + 2 * $n)) - port@$((16000 + 2 * $n)) - rpcport@$((18000 + 2 * $n)) - rpc path: $NODE_DIR/$NODES_NUM/cypher.ipc"
       $CYPHER  --nogas  --onetport $((7100 + 2 * $n)) --nat "none" --tps $EnableFlags --powrangemode $PRMV --localtest $LOCALIP --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal,miner,txpool --port $((16000 + 2 * $n)) --rpcport $((18000 + 2 * $n)) --verbosity "$LOGLEVEL" --datadir "$NODE_DIR/$NODES_NUM" --networkid $NetWorkId --gcmode archive --bootnodes "$BOOTNODE"  2>"$NODE_DIR/$NODES_NUM/$NODES_NUM.log" &

       $CYPHER attach $NODE_DIR/$NODES_NUM/cypher.ipc

}
csrestart_node()
{
    log "console restart $NODES_NUM node...."
        n=$(($1 + $NODES_NUM))
        $CYPHER   --onetport $((7100 + 2 * $n)) --nat "none" --tps $EnableFlags  --powrangemode $PRMV  --ipencdis $IPENCDISVALUE --powrangemode $PRMV --localtest $LOCALIP --rpc --rpccorsdomain "*" --rpcaddr 0.0.0.0 --rpcapi cph,web3,personal,miner,txpool --port $((16000 + 2 * $n)) --rpcport $((18000 + 2 * $n)) --verbosity "$LOGLEVEL" --datadir "$NODE_DIR/$NODES_NUM" --networkid $NetWorkId --gcmode archive --bootnodes "$BOOTNODE"  console



}

clean_db()
{
    log "Clean $NODES_NUM nodes' db, keystore is reserved."
    for n in $( seq $NODES_NUM ); do
        rm -rf $NODE_DIR/$n/cypher $NODE_DIR/$n/cypher.ipc $HOME/*.log
    done


}
cldbf()
{
    log "Clean $NODES_NUM nodes' db, keystore is reserved."
    for n in $( seq $NODES_NUM ); do
        rm -rf $NODE_DIR/$n/cypher $NODE_DIR/$n/cypher.ipc $NODE_DIR/$n/output.log $HOME/*.log
    done
}

log_dangerous()
{
    log "dangerous"
}

#
# confirm_do: prompt user to input y/Y to confirm before doing somcphing dangerous
# - argument 1: prompt information
# - argument 2: dangerous function
#
# example: confirm_do "Are you sure to delete database? " log_dangerous
#
confirm_do()
{
    read -p "$1" -n 2 -r
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        # do dangerous stuff
        "$2"
    fi
}

#--nat=extip:119.123.199.243
# parameters check

[ "$#" -eq 0 ] && die_usage

if [[ "$1" == "list" ]];then
    ps -a |grep "[r]pcaddr"
    exit 0
fi

if [[ "$1" == "kill" ]];then
    killall -HUP cypher
    exit 0
fi

rm_node()
{
    log "Clean all node data."
    rm -rf "$NODE_DIR"
}

if [[ "$1" == "$CLEAN" ]];then
    confirm_do "Are you sure to delete chain database including keystore?[y/N] " rm_node
    exit 0
fi

if ! [[ -x "$CYPHER" ]];then
    die "$CYPHER not found"
fi

if [[ "$1" == "$INIT"  || "$1" == "$CLEANDB" || "$1" == "$FORCECLEANDB" || "$1" == "$APPEND" || "$1" == "$STOP" || "$1" == "$NEWACCOUNT" || "$1" == "$LISTACCOUNT" || "$1" == "$CONSOLE" || "$1" == "$ATTACH" || "$1" == "$CLNODE" || "$1" == "$RESTART" ]];then
    NODES_NUM=$2

else
    NODES_NUM=$1
fi
if [[ "$1" == "$CONSOLE" ]];then

    console_node
    exit 0
fi

if [[ "$1" == "$ATTACH" ]];then

    attach_node
    exit 0
fi


if [[ "$1" == "$CLNODE" ]];then

    cldbf
    exit 0
fi

if [[ "$1" == "$RESTART" ]];then

    csrestart_node
    exit 0
fi

if [[ "$1" == "$LISTACCOUNT" ]];then
    list_account
    exit 0
fi


#log "$NODES_NUM"

if [[ "$1" != "$CONSOLE" ]];then
  if ! [[ "$NODES_NUM" =~ ^[1-9][0-9]*$ ]];then
    die "Invalid nodes number."
  fi
fi

if [[ "$NODES_NUM" -gt "$NODES_MAX" ]]; then
    log "Too many nodes to run, max number is 10"
    NODES_NUM=$NODES_MAX
fi


# if already running, do nothing
RUNNING_NODES_NUM=`ps -a | grep "[r]pcaddr" | awk 'END{ print NR }'`
#log "$RUNNING_NODES_NUM"
if [[ "$RUNNING_NODES_NUM" -gt 0 ]]; then
    if [[ "$1" == "$STOP" ]];then
        PID=`ps -a | grep "[r]pcaddr" | awk -v line="$NODES_NUM" 'FNR == line { print $1 }'`

        if [[ "$NODES_NUM" -le "$RUNNING_NODES_NUM" ]];then
            log "Stop node $NODES_NUM, pid = $PID"
            kill -9 $PID
        fi
        exit 0
    fi


    if [[ "$1" == "$APPEND" ]];then
        append_node $RUNNING_NODES_NUM $NODES_NUM
        exit 0
    else
      if [[ "$1" != "$CONSOLE" ]];then
        log "$RUNNING_NODES_NUM nodes are running, kill them before starting new nodes."
        exit 0
      fi
    fi
fi

if [[ "$1" == "$NEWACCOUNT" ]];then
    new_account
    exit 0
fi


if [[ "$1" == "$CLEANDB" ]];then
    confirm_do "Are you sure to delete chain database except keystore?[y/N] " clean_db
    exit 0
fi

if [[ "$1" != "$CONSOLE" ]];then
if [[ "$1" == "$INIT" ]];then
    init_node
else
   append_node 0 $NODES_NUM
fi


exit 0

fi
