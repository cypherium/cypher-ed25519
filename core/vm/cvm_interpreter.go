package vm

import (
	"fmt"
	//	"reflect"
	"strings"

	"github.com/cypherium/cypherBFT/accounts/abi"
	"github.com/cypherium/cypherBFT/common"
	"github.com/cypherium/cypherBFT/cvm"
	"github.com/cypherium/cypherBFT/params"
)

// ConfigJVM are the configuration options for the Interpreter
type ConfigJVM struct {
	// Debug enabled debugging Interpreter options
	Debug bool
	// Tracer is the op code logger
	Tracer Tracer
	// NoRecursion disabled Interpreter call, callcode,
	// delegate call and create.
	NoRecursion bool
	// Enable recording of SHA3/keccak preimages
	EnablePreimageRecording bool
	// JumpTable contains the EVM instruction table. This
	// may be left uninitialised and will be set to the default
	// table.
	//??JumpTable [256]operation
}

// JVMInterpreter represents an EVM interpreter
type JVMInterpreter struct {
	evm      *EVM
	cfg      Config
	gasTable params.GasTable

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse

	cvm           *cvm.CVM
	contract      *Contract
	contractAddr  string
	callerAddress string
}

// NewJVMInterpreter returns a new instance of the Interpreter.
func NewJVMInterpreter(evm *EVM, cfg Config) *JVMInterpreter {
	if params.DisableJVM {
		return nil
	}
	return &JVMInterpreter{
		evm:      evm,
		cfg:      cfg,
		gasTable: evm.ChainConfig().GasTable(evm.BlockNumber),
		cvm:      cvm.VM,
	}
}

//Run Interpreter do
func (in *JVMInterpreter) Run(contract *Contract, input []byte) (ret []byte, err error) {
	if params.DisableJVM {
		return nil, fmt.Errorf("JVM disabled!")
	}

	NP := 32
	n := len(input)
	methodName := ""
	methodArgs := []byte{}

	for n >= (4 + NP) {
		methodName = string(VMgetSBytes(input[n-NP:n], NP, "string"))
		p0 := strings.Index(methodName, "@")
		if p0 < 0 {
			NP = NP + 32
			continue
		}
		methodName = methodName[p0+1:]
		break
	}
	if n-NP > 4 {
		methodArgs = input[4 : n-NP]
	}

	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}
	contract.Input = input
	in.contract = contract
	in.contractAddr = contract.Address().String()
	in.callerAddress = contract.Caller().String()

	in.cvm.In = in

	//计算class的 运算量、内存、和存储

	//javaCode, err := bitutil.DecompressBytes(contract.Code, 846)
	//javaCode := contract.Code //make([]byte, len(contract.Code)*2)
	//javaCode, err := hexutil.Decode(string(contract.Code))
	//rlp.DecodeBytes(contract.Code, javaCode)
	//in.evm.Context, in.evm.StateDB,
	//res, err := cvm.StartVM( contract.Code, "", methodName,  methodArgs)

	res, err := in.startVM(contract.Code, "_cypher_contract", methodName, methodArgs)
	//in.startVM(contract.Code, "", methodName,  methodArgs)
	if err != nil {
		fmt.Println(err)
		return res, err
	}

	if res == nil && methodName == "" {
		return contract.Code, nil
	}

	//in.returnData = resBytes
	/*
		switch {
		case err == errExecutionReverted:
			return res, errExecutionReverted
		case err != nil:
			return nil, err
		}
	*/
	return res, nil
}

// CanRun tells if the contract, passed as an argument, can be
// run by the current interpreter.
func (in *JVMInterpreter) CanRun(code []byte) bool {
	if params.DisableJVM {
		return false
	}

	//try to find java magic
	if len(code) > 8 && code[0] == 0xCA && code[1] == 0xFE && code[2] == 0xBA && code[3] == 0xBE {
		return true
	}
	return false
}

// IsReadOnly reports if the interpreter is in read only mode.
func (in *JVMInterpreter) IsReadOnly() bool {
	return in.readOnly
}

// SetReadOnly sets (or unsets) read only mode in the interpreter.
func (in *JVMInterpreter) SetReadOnly(ro bool) {
	in.readOnly = ro
}

func (in *JVMInterpreter) startVM(memCode []byte, className, methodName string, javaArgs []byte) ([]byte, error) {
	if params.DisableJVM {
		return nil, fmt.Errorf("JVM disabled!")
	}
	argsLen := len(javaArgs)

	if className == "" {
		className = "_cypher_contract"
	}
	if methodName == "" { //main,create contract
		ret := in.cvm.StarMain(memCode, className)
		//in.contract.Gas += uint64(cvm.VM.TotalPc) * params.TxDataZeroGas
		if ret == "" {
			return memCode, nil
		}
		s, _ := VMpackToRes("string", ret)
		return s, fmt.Errorf("Exception in main class")

	} else if argsLen == 0 && (methodName == "owner()" || methodName == "symbol()" || methodName == "name()" || methodName == "totalSupply()") {
		res := JDK_getContractValue(methodName)
		if methodName == "totalSupply()" {
			return res.Bytes(), nil
		}
		s := VMhashByteToRes(res.Bytes())
		//fmt.Println(s)
		return s, nil
	} else if methodName == "balanceOf(address)" {
		if argsLen == 0 {
			return nil, fmt.Errorf("balanceOf: not found address")
		}
		s := common.Bytes2Hex(VMgetSBytes(javaArgs, -1, "address"))
		hashv, err := JDK_getContractBalance(s)
		if err != nil {
			return nil, err
		}
		//hashv.Big()
		return hashv.Bytes(), nil
	}

	ret := in.cvm.StartFunction(memCode, className, methodName, javaArgs)
	//in.contract.Gas += uint64(cvm.VM.TotalPc) * params.TxDataZeroGas
	s, err := VMpackToRes("string", ret) //only return string
	return s, err
}

//VMpackToRes pack value for vm return to js
func VMpackToRes(stype string, v interface{}) ([]byte, error) {
	var arg abi.Argument
	def := fmt.Sprintf(`{"type": "%s" }`, stype)
	err := arg.UnmarshalJSON([]byte(def))
	if err != nil {
		return nil, err
	}
	args := abi.Arguments{arg}
	return args.Pack(v)
}

//VMhashByteToRes  convert simple string to vm return, only simple function call
func VMhashByteToRes(inBuf []byte) []byte {
	res := []byte{}
	n := len(inBuf)
	i := 0
	for i < n && inBuf[i] == 0 {
		i++
	}

	zeroBuf := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} //先简单一点
	if i == n {
		return zeroBuf
	}
	res = append(res, zeroBuf...)
	res[31] = 32

	res = append(res, zeroBuf...)
	res[63] = byte(n - i) //先简单一点，假设长度小于32,大于32要做复杂考虑

	res = append(res, inBuf[i:]...)
	res = append(res, zeroBuf[32-i:]...) //后面补0

	return res
}

//VMgetSBytes covert param bytes to normal bytes
func VMgetSBytes(b []byte, n int, stype string) []byte {
	if n <= 0 {
		n = len(b)
	}

	p0, p1 := 0, n
	if b[0] != 0 { //"string"
		i := 0
		for ; i < n; i++ {
			if b[i] == 0 {
				break
			}
		}
		p1 = i
	} else {
		i := 0
		for ; i < n; i++ {
			if b[i] != 0 {
				break
			}
		}
		p0 = i
	}

	return b[p0:p1]
}

func CVM_init() {
	if params.DisableJVM {
		return
	}

	//cvm.CVM_init(register_javax_cypher_cypnet)
}
