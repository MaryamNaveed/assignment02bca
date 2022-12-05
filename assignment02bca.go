package assignment02bca

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

type block struct {
	Data     []*transaction
	Hash     string
	PrevHash string
	Nonce    int
	Root     *MerkleTree
}

type transaction struct {
	ID string
}

type blockchain struct {
	blocks []*block
}

func (b *block) calculateHash() string { //Function to calcuate hash
	bytes, _ := json.Marshal(b.Data)
	// concatenate the dataset
	blockData := strconv.Itoa(b.Nonce) + string(bytes) + string(b.Root.RootNode.Data) //+ strconv.Atoi(b.prevHash) //Appending all the block data

	//Using SHA256 to calculate hash of the block
	hashval := sha256.New()
	hashval.Write([]byte(blockData))
	b.Hash = hex.EncodeToString(hashval.Sum(nil))
	return b.Hash
}

func (chain *blockchain) MineBlock(numZeros int, b *block) { //Function to mine the block
	min := 1000
	max := 9999
	nonce := rand.Intn(max-min) + min  //Making a random 4 digit nonce
	y := strings.Repeat("0", numZeros) //Setting number of trailing zeros to achieve target
	//Loop to keep on calculating the hash for random nonces until target is found
	for !strings.HasPrefix(b.Hash, y) {
		nonce = rand.Intn(max-min) + min
		b.Nonce = nonce
		b.calculateHash()

	}
	chain.AddBlock(b) //Add the mined block to the blockchain
}

func NewBlock(t []*transaction) *block { //Function to create a new block
	//Initializing all the transactions
	Block := &block{
		Data: t,
	}

	//Calculating root hash of merkel tree for the transactions of current block
	node := Block.HashTransactions()
	var p *MerkleTree = new(MerkleTree)
	p.RootNode = node
	Block.Root = p
	return Block
}

func (chain *blockchain) AddBlock(b *block) { //Function to add block to the blockchain
	prevBlock := chain.blocks[len(chain.blocks)-1] //Storing the previous block in the blockchain
	b.PrevHash = prevBlock.Hash                    //Storing the hash of the previous block
	chain.blocks = append(chain.blocks, b)         //Appending this block to the blockchain
}

func Genesis(b *block) *block { //function to initialize the genesis block

	return NewBlock(b.Data)
}

func (chain *blockchain) DisplayBlocks() { //Displaying all the block data]
	for _, block := range chain.blocks {
		fmt.Printf("Previous Hash: %s\n", block.PrevHash)
		for _, b := range block.Data {
			fmt.Printf("Data in Block: %v\n", b.ID)
		}
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Printf("Nonce: %d\n", block.Nonce)
		fmt.Printf("Root: %x\n", block.Root.RootNode.Data)
		fmt.Printf("------------------------------------------------------------------------\n")
	}
}

type MerkleTree struct {
	RootNode *MerkleNode
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode { //function to make a merkle node and hash it
	newNode := MerkleNode{}

	if left == nil && right == nil {
		hashval := sha256.Sum256(data)
		newNode.Data = hashval[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hashVal := sha256.Sum256(prevHashes)
		newNode.Data = hashVal[:]
	}

	newNode.Left = left
	newNode.Right = right

	return &newNode
}

func NewMerkleTree(data [][]byte) *MerkleTree { //Function to make the merkle tree
	var parents []MerkleNode

	for float64(int(math.Log2(float64(len(data))))) != math.Log2(float64(len(data))) {
		data = append(data, data[len(data)-1])
	}

	for _, dat := range data {
		newNode := NewMerkleNode(nil, nil, dat)
		parents = append(parents, *newNode)
	}

	for i := 0; i < int(math.Log2(float64(len(data)))); i++ {
		var children []MerkleNode

		for j := 0; j < len(parents); j += 2 {
			newNode := NewMerkleNode(&parents[j], &parents[j+1], nil)
			children = append(children, *newNode)
		}

		parents = children
	}

	merkletree := MerkleTree{&parents[0]}

	return &merkletree
}

func (b *block) DisplayMerkelTree() {
	var txHashes [][]byte

	for _, tx := range b.Data {
		txHashes = append(txHashes, tx.Serialize())
	}
	for _, tx := range txHashes {
		fmt.Printf("%x\n", tx)
	}
}

func (b *block) AddItem(item *transaction) []*transaction { //adding transaction to list of transactions
	b.Data = append(b.Data, item)
	return b.Data
}

func (b *transaction) Serialize() []byte { //function to serialize
	var res bytes.Buffer
	encoder := gob.NewEncoder(&res)

	err := encoder.Encode(b)

	Handle(err)
	return res.Bytes()
}

func (b *block) HashTransactions() *MerkleNode { //function to serialize the transactions
	var totalhashes [][]byte

	for _, hashval := range b.Data {
		totalhashes = append(totalhashes, hashval.Serialize())
	}
	tree := NewMerkleTree(totalhashes)
	return tree.RootNode
}

func Handle(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func changeBlock(b *block, t *transaction, index int) {
	b.Data[index] = t            //Changing the block
	node := b.HashTransactions() //Hashing the transactions again

	//Forming the tree again for new value of root node
	var p *MerkleTree = new(MerkleTree)
	p.RootNode = node
	b.Root = p
}

func (chain *blockchain) verifyChain() bool {
	for _, block := range chain.blocks { //traversing the entire chain
		prevHash := block.Hash           //storing curret blockHash
		newHash := block.calculateHash() //storing hash after recalculating

		if prevHash != newHash { //if recalculated hash not same, block has been changed
			fmt.Println("Chain Invalid")
			return false
		}
	}
	return true
}

func DisplayMerkelRec(m *MerkleNode, space int) {
	if m == nil {
		return
	}

	space = space + 2

	DisplayMerkelRec(m.Right, space)

	fmt.Println()

	for i := 2; i < space; i++ {
		fmt.Print(" ")
	}

	fmt.Printf("%x\n", m.Data)

	DisplayMerkelRec(m.Left, space)

}

func (b *block) DisplayMerkel() {

	fmt.Println("-------------------Merkle Tree-----------------------")

	DisplayMerkelRec(b.Root.RootNode, 0)

	fmt.Println("-----------------------------------------------------")

}

type node struct {
	SERVER_HOST string
	SERVER_PORT string
	SERVER_TYPE string

	neighbours   []*node
	transactions []*transaction
	chain        blockchain
}

func NewNode(SH string, SP string, ST string) *node { //Function to create a new node

	Node := &node{
		SERVER_HOST: SH,
		SERVER_PORT: SP,
		SERVER_TYPE: ST,
	}
	return Node
}

func createBootstrapClient(bootstrapnode *node) node {
	//establish connection
	connection, err := net.Dial(bootstrapnode.SERVER_TYPE, bootstrapnode.SERVER_HOST+":"+bootstrapnode.SERVER_PORT)

	if err != nil {
		fmt.Println(err)

	}
	defer connection.Close()

	//receiving port
	buffer := make([]byte, 1024)
	mLen, err := connection.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	fmt.Println("Received Port: ", string(buffer[:mLen]))

	//sending node info
	newnode := &node{SERVER_HOST: "127.0.0.1", SERVER_PORT: string(buffer[:mLen]), SERVER_TYPE: "tcp"}

	gobEncoder := gob.NewEncoder(connection)
	err = gobEncoder.Encode(newnode)

	if err != nil {
		fmt.Println(err)
	}

	for {
		var mynode node
		dec := gob.NewDecoder(connection)
		err = dec.Decode(&mynode)
		if mynode.SERVER_HOST == "" {
			break
		}

		newnode.neighbours = append(newnode.neighbours, &mynode)

		mynode.neighbours = append(mynode.neighbours, newnode)
	}

	return *newnode

}

func (n *node) createClient(n2 *node, trans *transaction) {

	//establish connection
	connection, err := net.Dial(n2.SERVER_TYPE, n2.SERVER_HOST+":"+n2.SERVER_PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer connection.Close()

	buffer := "Flood"

	gobEncoder := gob.NewEncoder(connection)
	err = gobEncoder.Encode(buffer)
	err = gobEncoder.Encode(n)

	fmt.Println("Sending transaction to: ", n2.SERVER_PORT)

	err1 := gobEncoder.Encode(&trans)

	if err1 != nil {
		fmt.Println(err1)
	}

}

func (n *node) createClientStart(n2 *node) {

	//establish connection
	connection, err := net.Dial(n2.SERVER_TYPE, n2.SERVER_HOST+":"+n2.SERVER_PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer connection.Close()

	buffer := "Start"

	gobEncoder := gob.NewEncoder(connection)
	err = gobEncoder.Encode(buffer)
	err = gobEncoder.Encode(n)

}

func createServer(n *node) {
	fmt.Println("Server Running...")
	server, err := net.Listen(n.SERVER_TYPE, n.SERVER_HOST+":"+n.SERVER_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	fmt.Println("Listening on " + n.SERVER_HOST + ":" + n.SERVER_PORT)
	fmt.Println("Waiting for client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		processClient(n, connection)
	}
}
func processClient(n *node, connection net.Conn) {

	// buffer := make([]byte, 1024)
	// _, err := connection.Read(buffer)
	// if err != nil {
	// 	fmt.Println("Error reading:", err.Error())
	// }

	// fmt.Println("Received Msg: ", string(buffer[:]))

	var buffer string

	dec := gob.NewDecoder(connection)

	err := dec.Decode(&buffer)

	if string(buffer[:5]) == "Start" {
		var nodeclient node

		err = dec.Decode(&nodeclient)
		if err != nil {
			fmt.Println(err)
		}

		found := false
		for i := 0; i < len(n.neighbours); i++ {
			if n.neighbours[i].SERVER_HOST == nodeclient.SERVER_HOST && n.neighbours[i].SERVER_PORT == nodeclient.SERVER_PORT {
				found = true
			}
		}

		if found == false {
			n.neighbours = append(n.neighbours, &nodeclient)
		}

		n.DisplayNeigbours()

	} else if string(buffer[:5]) == "Flood" {
		var nodeclient node
		err = dec.Decode(&nodeclient)
		if err != nil {
			fmt.Println(err)
		}

		found := false
		for i := 0; i < len(n.neighbours); i++ {
			if n.neighbours[i].SERVER_HOST == nodeclient.SERVER_HOST && n.neighbours[i].SERVER_PORT == nodeclient.SERVER_PORT {
				found = true
			}
		}

		if found == false {
			n.neighbours = append(n.neighbours, &nodeclient)
		}

		// n.DisplayNeigbours()

		fmt.Println("Receiving transaction from: ", nodeclient.SERVER_PORT)

		var trans transaction
		// dec1 := gob.NewDecoder(connection)
		err1 := dec.Decode(&trans)

		if err1 != nil {
			fmt.Println(err1)
		} else {
			istransFound := false

			for i := 0; i < len(n.transactions); i++ {
				if n.transactions[i].ID == trans.ID {
					istransFound = true
				}
			}

			if istransFound == false {
				n.transactions = append(n.transactions, &trans)
				for i := 0; i < len(n.neighbours); i++ {
					if n.neighbours[i].SERVER_HOST == nodeclient.SERVER_HOST && n.neighbours[i].SERVER_PORT == nodeclient.SERVER_PORT {
					} else {
						n.createClient(n.neighbours[i], &trans)
					}
				}
				n.DisplayTransaction()
			}

		}

	} else if string(buffer[:5]) == "Block" {
		var nodeclient node
		err = dec.Decode(&nodeclient)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println("Receiving block from: ", nodeclient.SERVER_PORT)

		var block1 block
		// dec1 := gob.NewDecoder(connection)
		err1 := dec.Decode(&block1)

		if err1 != nil {
			fmt.Println(err1)
		} else {

			//verify block

			verified := n.chain.verifyChain()

			block1.calculateHash()

			y := strings.Repeat("0", 1)
			if !strings.HasPrefix(block1.Hash, y) {

				verified = false
			}

			if verified == true {
				isPresent := false
				//check if block is already present
				for i := 0; i < len(n.chain.blocks); i++ {
					if n.chain.blocks[i].Hash == block1.Hash {
						isPresent = true
					}
				}

				if isPresent == false {
					//add to chain
					n.chain.AddBlock(&block1)

					//remove transactions locally
					transactions := n.transactions
					for i := 0; i < len(block1.Data); i++ {
						for j := 0; j < len(transactions); j++ {

							if block1.Data[i].ID == transactions[j].ID {
								transactions = append(transactions[0:j], transactions[j+1:]...)
								break
							}
						}

					}

					n.transactions = transactions

					//flood to neighbours

					for i := 0; i < len(n.neighbours); i++ {
						if n.neighbours[i].SERVER_HOST == nodeclient.SERVER_HOST && n.neighbours[i].SERVER_PORT == nodeclient.SERVER_PORT {
						} else {
							n.createClientBlock(n.neighbours[i], &block1)
						}
					}

					n.chain.DisplayBlocks()
					n.DisplayTransaction()

				}
			}

		}
	}

	connection.Close()
}

func newNode(bootstrapnode *node) node {

	newnode := createBootstrapClient(bootstrapnode)

	// for i := 0; i < len(newnode.neighbours); i++ {
	// 	if newnode.neighbours[i].SERVER_HOST == bootstrapnode.SERVER_HOST && newnode.neighbours[i].SERVER_PORT == bootstrapnode.SERVER_PORT {

	// 	} else {
	// 		go newnode.createClient(newnode.neighbours[i])
	// 	}

	// }

	return newnode

}

func (mynode *node) DisplayNeigbours() { //Displaying all the node data]
	fmt.Println("------------------Neighbours-------------------")
	for _, node := range mynode.neighbours {
		fmt.Printf("PORT: %s\n", node.SERVER_PORT)

	}
	fmt.Println("-----------------------------------------------")

}

func flooding(newnode *node, trans *transaction) {

	istransFound := false

	for i := 0; i < len(newnode.transactions); i++ {
		if newnode.transactions[i].ID == trans.ID {
			istransFound = true
		}
	}
	if istransFound == false {
		newnode.transactions = append(newnode.transactions, trans)
	}

	for i := 0; i < len(newnode.neighbours); i++ {
		newnode.createClient(newnode.neighbours[i], trans)
	}

	newnode.DisplayTransaction()

}

func (newnode *node) DisplayTransaction() {

	fmt.Println("-----------------Transactions------------------")
	for _, t := range newnode.transactions {
		fmt.Println(t.ID)

	}
	fmt.Println("-----------------------------------------------")
}

func (n *node) createClientBlock(n2 *node, block1 *block) {

	//establish connection
	connection, err := net.Dial(n2.SERVER_TYPE, n2.SERVER_HOST+":"+n2.SERVER_PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer connection.Close()

	buffer := "Block"

	gobEncoder := gob.NewEncoder(connection)
	err = gobEncoder.Encode(buffer)
	err = gobEncoder.Encode(n)

	fmt.Println("Sending transaction to: ", n2.SERVER_PORT)

	fmt.Println("Length: ", len(block1.Data))

	err1 := gobEncoder.Encode(&block1)

	if err1 != nil {
		fmt.Println(err1)
	}

}

func blockflooding(newnode *node, block1 *block) {
	for i := 0; i < len(newnode.neighbours); i++ {
		newnode.createClientBlock(newnode.neighbours[i], block1)
	}

	newnode.chain.DisplayBlocks()

}

func Menu() {

	portbootstrap := "5000"

	items := []*transaction{}
	block11 := &block{Data: items}
	block11.AddItem(&transaction{ID: ""})

	//Making the genesis block
	gen := Genesis(block11)
	gen.PrevHash = "0"
	gen.Nonce = 0
	gen.calculateHash()

	//Initiailizing the chain
	c := blockchain{[]*block{gen}}

	fmt.Println(len(c.blocks))

	bootstrapnode := &node{SERVER_HOST: "127.0.0.1", SERVER_PORT: portbootstrap, SERVER_TYPE: "tcp", chain: c}

	newnode := newNode(bootstrapnode)
	newnode.chain = c
	choice := "0"

	go createServer(&newnode)

	for i := 0; i < len(newnode.neighbours); i++ {
		go newnode.createClientStart(newnode.neighbours[i])
	}

	newnode.DisplayNeigbours()

	for {

		fmt.Println("What to do?")
		fmt.Println("1. Send Transaction")
		fmt.Println("2. Mine Block")
		fmt.Scan(&choice)

		if choice == "1" {
			transactionID := ""
			fmt.Println("Enter Transaction")
			fmt.Scan(&transactionID)
			flooding(&newnode, &transaction{ID: transactionID})
		} else if choice == "2" {
			if len(newnode.transactions) >= 5 {

				items := []*transaction{}
				block1 := &block{Data: items}

				for i := 0; i < 5; i++ {
					block1.AddItem(newnode.transactions[i])
				}

				block4 := NewBlock(block1.Data)

				fmt.Println(len(newnode.chain.blocks))

				newnode.chain.MineBlock(1, block4)

				newnode.transactions = newnode.transactions[5:]

				blockflooding(&newnode, block4)

			}

		}

		choice = "0"

	}

}

type p2pNetwork struct {
	nodes []*node
}

func (network *p2pNetwork) AddNode(n *node) {
	network.nodes = append(network.nodes, n)
}

func createBootstrapServer(n *node) {
	network := &p2pNetwork{}

	portcurrent := 5001

	fmt.Println("Server Running...")
	server, err := net.Listen(n.SERVER_TYPE, n.SERVER_HOST+":"+n.SERVER_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	fmt.Println("Listening on " + n.SERVER_HOST + ":" + n.SERVER_PORT)
	fmt.Println("Waiting for client...")
	for {
		connection, err := server.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("client connected")

		//sending port
		_, err = connection.Write([]byte(strconv.Itoa(portcurrent)))
		if err != nil {
			fmt.Println(err)
		}

		//sending some random nodes
		processBootstrapClient(connection, network, portcurrent)

		portcurrent += 1
	}
}
func processBootstrapClient(connection net.Conn, network *p2pNetwork, port int) {

	//receiving block info
	var newnode node
	dec := gob.NewDecoder(connection)
	err := dec.Decode(&newnode)
	if err != nil {
		fmt.Println(err)
	}

	count := (len(network.nodes) / 2) + 1

	var neighboursArr []int

	if len(network.nodes) == 0 {
		count = 0
	}

	for i := 0; i < count; {
		random := rand.Intn(count)
		fmt.Println(i, random)

		found := false

		for _, x := range neighboursArr {
			if x == random {
				found = true

			}
		}

		if found == false {
			neighboursArr = append(neighboursArr, random)
			gobEncoder := gob.NewEncoder(connection)
			erro := gobEncoder.Encode(&network.nodes[random])
			if erro != nil {
				fmt.Println(erro)
			}
			i++
		}
	}

	network.nodes = append(network.nodes, &newnode)

	mynode := &node{}
	gobEncoder := gob.NewEncoder(connection)
	err = gobEncoder.Encode(mynode)

	connection.Close()

	network.DisplayNetwork()
}

func (network *p2pNetwork) DisplayNetwork() { //Displaying all the node data
	fmt.Println("------------------Network-------------------")
	for _, node := range network.nodes {
		fmt.Printf("PORT: %s\n", node.SERVER_PORT)

	}
	fmt.Println("-----------------------------------------------")

}

func Boot() {
	portbootstrap := "5000"

	bootstrapnode := &node{SERVER_HOST: "127.0.0.1", SERVER_PORT: portbootstrap, SERVER_TYPE: "tcp"}

	createBootstrapServer(bootstrapnode)
}
