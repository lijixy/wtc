#!/usr/bin/env node

/**
 * Ellipal
 */

'use strict'

/**
 * Configurables.
 */
const TESTING = false
const RPC_SERVICE = TESTING ? 'https://explorer.thetatoken.org' : 'https://explorer.thetatoken.org'
const CHAIN_ID = TESTING ? "mainnet" : "mainnet"
const SERVER_PORT = 9521 // Connector service port
const BIND_IP = TESTING ? '0.0.0.0' : '0.0.0.0'

const Web3 = require("web3")
const web3 = new Web3(new Web3.providers.HttpProvider(RPC_SERVICE))
const ethtx = require('ethereumjs-tx')
const http = require('http')
const url = require('url')
const BN = require('bn.js')

/**
 * Error codes.
 */
const ERR_BADSIG = 40100 // submitted tx didn't pass verification.
const ERR_OVERSPENDING = 40200 // user's balance is insufficient for the transaction.
const ERR_APIDATA = 50300 // API returned unparseable message.
const ERR_APINETWORK = 50400 // API site communication error.

process.title = 'thetacon'

const server = http.createServer(httpHandler).listen(SERVER_PORT, BIND_IP)
console.log(server)
server.setTimeout(60000) // 60s timeout

async function httpHandler(clientReq, serverRsp) {
    serverRsp.setHeader('Content-Type', 'text/plain')
    console.log(new Date().toISOString(), '[REQUEST]', clientReq.socket.remoteAddress, clientReq.url)
    var pathList = url.parse(clientReq.url).pathname.split('/')
	console.log(pathList)
    var txData = await loadTxData(pathList);
	console.log(txData)
    if (!txData) {
        badRequest(serverRsp)
        return
    }
    if (pathList[1] == 'thetareq') {
		console.log("liji---testtheta")
        // Make a tx.
        var uTx = new ethtx(txData)
		console.log(uTx)
        var hashStr = '0x' + uTx.hash(false).toString('hex')
        uTx.v = CHAIN_ID
        serverRsp.write(JSON.stringify({
            status: 'ok',
            hash: hashStr,
            tx: '0x' + uTx.serialize().toString('hex')
        }, null, 2))
        serverRsp.statusCode = 200
        serverRsp.end()
    } else if (pathList[1] == 'thetasend') {
        // Send a tx with signature.
        var sTx = new ethtx(txData)
		console.log("lijitest--sendTHETA")
		console.log(sTx)
        var sTxStr = '0x' + sTx.serialize().toString('hex')
        web3.eth.sendSignedTransaction(sTxStr, (err, hash) => {
            if (!err) {
                // Success.
                console.log(new Date().toISOString(), '[TX ID]', hash)
                serverRsp.write(JSON.stringify({
                    status: 'ok',
                    tx: sTxStr,
                    txid: hash
                }, null, 2))
                serverRsp.statusCode = 200
                serverRsp.end()
            } else {
                // Report error.
                console.log(new Date().toISOString(), '[SEND ERR]', err.toString())
                serverRsp.write(JSON.stringify({
                    status: 'error',
                    code: ERR_BADSIG,
                    msg: err.toString()
                }, null, 2))
                serverRsp.statusCode = 200
                serverRsp.end()
            }
        })
    } else {
        // Unsupported requests or unmatching number of params.
        badRequest(serverRsp)
    }
}

/**
 * Handler for bad requests.
 */
function badRequest(rsp) {
    rsp.statusCode = 400 // "Bad Request"
    console.log(new Date().toISOString(), '[ERROR] Bad request.')
    rsp.end()
}

/**
 * Report "business error" rather than low-level 400 error.
 */
function errorReport(rsp, code) {
    rsp.statusCode = 200 // "OK"
    rsp.write(JSON.stringify({
        status: 'error',
        code: code,
    }, null, 4))
    console.log(new Date().toISOString(), '[ERROR] Code:', code)
    rsp.end()
}

async function loadTxData(plist) {
    /**
     * Address string must start with '0x' and decodes to 20 bytes.
     */
    function checkAddr(a) {
        if (a[0] != '0' || a[1] != 'x') return false
        try {
            var b = new Buffer.from(a.slice(2), 'hex')
        } catch (e) {
            return !e
        }
        if (b.length != 20) return false
        return true
    }

    if (plist[1] != 'thetareq' && plist[1] != 'thetasend') return null
    if (plist.length < 6) return null

    var txdata = {
        chainId: CHAIN_ID,
    }
	if(plist[1] == 'thetareq'){
		txdata.gasLimit=plist[6]
	}
	else{
		txdata.gasLimit=plist[9]
	}
    if (!checkAddr(plist[2])) return null
    txdata.from = plist[2]
	/*
	var promisenonce = Promise.resolve(web3.eth.getTransactionCount(plist[2]));
	console.log(promisenonce)
	promiseNonce(promisenonce).then(function(value){
		console.log(value)
		txdata.nonce=value
	}).catch(error => console.log(error))*/
	
    txdata.nonce=await web3.eth.getTransactionCount(plist[2]).then(data=>{
		console.log("lijitestget theta nonce")
		console.log(data)
		console.log(txdata.from )
		return Promise.resolve('0x' + data.toString(16))
	})

	/*
	function promiseNonce(promisenonce) { 
        web3.eth.getTransactionCount(promisenonce).then(data=>{
		console.log("lijitestget nonce")
		console.log(data)
		return data
	})
   }*/
	//txdata.nonce=web3.eth.getTransactionCount(plist[2]).then(function(res){
	//	resolve(res)
	//	}
	//)
	//txdata.nonce=web3.eth.getTransactionCount(plist[2])
	
	//txdata.nonce=web3.eth.getTransactionCount(plist[2]).then(data=>{
	//	console.log("lijitestget nonce")
	//	console.log(data)
	//	return Promise.resolve(data)
	//})
	
	console.log("lijitest=theta==nonce")
	console.log(txdata.nonce)
	
    //txdata.nonce = web3.eth.getTransactionCount(plist[2])
    if (!checkAddr(plist[3])) return null
    txdata.to = plist[3]
    txdata.gasPrice = plist[4]
	console.log("lijitest-theta-get--loadData")
	console.log("txData",txdata)
    try {
        var big = new BN(plist[5], 10)
        txdata.value = '0x' + big.toString(16)
    } catch (e) {
        return null
    }
    if (plist[1] == 'thetasend') {
        if (plist.length != 10) return null
        txdata.r = plist[6]
        txdata.s = plist[7]
        txdata.v = parseInt(plist[8]) + CHAIN_ID * 2 + 8
    }
    console.log('TX DATA:', txdata)
    return txdata
}
/*
function promiseNonce(promisenonce) { 
  web3.eth.getTransactionCount(promisenonce).then(data=>{
		console.log("lijitestget nonce")
		console.log(data)
		return data
	})
}*/

const Hexstring2btye = (str)=> {
    let pos = 0;
    let len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    let hexA = new Array();
    for (let i = 0; i < len; i++) {
        let s = str.substr(pos, 2);
        let v = parseInt(s, 16);
        hexA.push(v);
        pos += 2;
    }
    return hexA;
}
 
 
const Bytes2HexString = (b)=> {
    let hexs = "";
    for (let i = 0; i < b.length; i++) {
        let hex = b[i].toString(16);
        if (hex.length == 1) {
            hex = '0' + hex;
        }
        hexs += hex.toUpperCase();
    }
    return hexs;
}
