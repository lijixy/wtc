#!/usr/bin/env node

/**
 * Ellipal
 */

'use strict'

/**
 * Configurables.
 */
 
const BASE_URL = "https://api-wallet.thetatoken.org";

const DEFAULT_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
};
 
 
const TESTING = false
const RPC_SERVICE = TESTING ? 'https://explorer.thetatoken.org' : 'https://explorer.thetatoken.org'
const CHAIN_ID = TESTING ? "mainnet" : "mainnet"
const SERVER_PORT = 8083 // Connector service port
const BIND_IP = TESTING ? '0.0.0.0' : '0.0.0.0'


const fetch = require('node-fetch');
const Web3 = require("web3")
const web3 = new Web3(new Web3.providers.HttpProvider(RPC_SERVICE))
const ethtx = require('ethereumjs-tx')
const http = require('http')
const url = require('url')
const BN = require('bn.js')
//const ThetaJS = require('./thetajs/thetajs.esm.js');
const BigNumber=require('bignumber.js');

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
    //var txData = await loadTxData(pathList);
	var txData=loadReturntxData(pathList);
	console.log(txData)
    if (!txData) {
        badRequest(serverRsp)
        return
    }
    if (pathList[1] == 'thetareq') {
		console.log("liji---testtheta")
        // Make a tx.
        var uTx = await unsignedSendTx(txData)
		//var uTx=new ethtx(txData["transaction"])
		console.log("lijiustx-------");
		console.log(uTx)
		var uTXhash=TxSigner.serializeTx(uTx);
		console.log("uTxhash");
		console.log(uTXhash);
		
		
		///////////////////////////let signedRawTxBytesVPN = TxSigner.signAndSerializeTx(CHAIN_ID, uTx, "0x7b50eaa129c524f79b9eee756aecb22ada24ed4a1d7f2b2b1a88e69e333aaf6b");
		///////////////////////////console.log("liji signed VPN----");
		/////////////////////////////console.log(signedRawTxBytesVPN.toString('hex'));
        //let signedTxRaw = signedRawTxBytes.toString('hex');
		
		
        //Remove the '0x' until the RPC endpoint supports '0x' prefixes
        let signedTxRaw = uTXhash.substring(2);
		console.log(signedTxRaw);
		
		
        var hashStr = TxSigner.signTxtohash(CHAIN_ID,uTx)
        //uTx.v = CHAIN_ID
        serverRsp.write(JSON.stringify({
            status: 'ok',
            hash: hashStr.toString("hex").substring(2),
			unsigned_tx:signedTxRaw.toString("hex")
            //tx: '0x' + uTx.serialize().toString('hex')
        }, null, 2))
        serverRsp.statusCode = 200
        serverRsp.end()
    } else if (pathList[1] == 'thetasend') {
        var uTx = await unsignedSendTx(txData)
		console.log("ellipal send");
		uTx.inputs[0].signature=txData.transaction.signature.toLowerCase();
		console.log(uTx);
		
		
        // Send a tx with signature.
        //var sTx = new ethtx(txData)
		//console.log("lijitest--sendTHETA")
		//console.log(sTx)
		/**
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
		*/
	   //var signedTxed=TxSigner.serializeTxed(uTx,txData.transaction.signature).toString("hex");
	   //console.log("liji return json signedTxed");
	   //console.log(signedTxed);
	   var signedTx=TxSigner.serializeTx(uTx).toString("hex");
	   var hashStr = TxSigner.signTxtohash(CHAIN_ID,uTx)
	   let responseCreate=await createTransaction({data: signedTx.substring(2)}, {network: "mainnet"});
	   let responseJSONcreate = responseCreate;
	   console.log("liji return json create");
	   console.log(responseJSONcreate);
	   let statusinfo=responseJSONcreate["status"];
       if(statusinfo=="success"){
		   statusinfo="ok"
		   hashStr=responseJSONcreate["hash"]
	   }
       else{
		   hashStr="";
	   }	   
	   serverRsp.write(JSON.stringify({
	       status: statusinfo,
	       txid: hashStr,
           //unsigned_tx:signTx
	       //tx: uTx
	   }, null, 2))
	   serverRsp.statusCode = 200
	   serverRsp.end()
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
	
	let response =await fetchSequence("0x5c4839874D9deEE89eDF23FDf3a9435B4A31590b", {"network":"mainnet"});
	let responseJSON = response;
	let sequenceNum = parseInt(responseJSON['sequence']) + 1;
	txdata.nonce='0x' + sequenceNum.toString(16);
	
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




function badRequest(rsp) {
    rsp.statusCode = 400 // "Bad Request"
    console.log(new Date().toISOString(), '[ERROR] Bad request.')
    rsp.end()
}

function objectToQueryString(object) {
    if(!object){
        return "";
    }

    let queryString = Object.keys(object).map(function(key) {
        let val = object[key];
        if(val){
            return encodeURIComponent(key) + '=' + encodeURIComponent(object[key]);
        }
    }).join('&');

    if(queryString.length > 0){
        return "?" + queryString;
    }
    else{
        return "";
    }
}

function buildHeaders(additionalHeaders) {
    //TODO inject auth headers here...
    return Object.assign(DEFAULT_HEADERS, additionalHeaders);
}

function buildURL(path, queryParams) {
    let url = null;

    if(path.startsWith("http://") || path.startsWith("https://")){
        url = path + objectToQueryString(queryParams);
    }
    else{
        url = BASE_URL + path + objectToQueryString(queryParams);
    }
	//console.log(url);

    return url;
}

function sendRequest(path, method, additionalHeaders, queryParams, body) {
    let url = buildURL(path, queryParams);
    let headers = buildHeaders(additionalHeaders);

    let opts = {
        method: method,
        headers: headers,
    };

    if (body) {
        opts['body'] = JSON.stringify(body);
    }

    return fetch(url, opts).then(res => res.json()).then();
}

async function fetchSequence(address, queryParams) {
        let path = `/sequence/${ address }`;
        return GET(path, null, queryParams);
}

async function createTransaction(body, queryParams) {
       let path = `/tx`;
       return POST(path, null, queryParams, body);
}



function GET(path, headers, queryParams) {
    return sendRequest(path, "GET", headers, queryParams);
}
function POST(path, headers, queryParams, body) {
    return sendRequest(path, "POST", headers, queryParams, body);
}



function loadReturntxData(plist){
	let signinfo=""
	if(plist[1]=="thetasend"){
		signinfo='0x' + plist[6] + plist[7] + (parseInt(plist[8], 16) - 27).toString().padStart(2, '0');
	}
	
	let loadDatatx={
		props:{
			network:"mainnet",
			transaction:{
				tokenType:"theta",
				from:plist[2],
				to:plist[3],
				amount:plist[4],
				transactionFee:plist[5],
				signature:signinfo,
				amountTFuel:plist[plist.length-1]
			}
		}
	}
	console.log("txDATQ---",loadDatatx["props"])
	return loadDatatx["props"];
}


async function unsignedSendTx(txData) {
	console.log(txData);
	console.log("liji--------------------------------------------");
	let tokenType="theta";
	let from=txData["transaction"]["from"];
	let to=txData["transaction"]["to"];
	let amount=txData["transaction"]["amount"];
	let transactionFee=txData["transaction"]["transactionFee"];
	let amountTFuel=txData["transaction"]["amountTFuel"]
	const ten18 = (new BigNumber(10)).pow(18); // 10^18, 1 Theta = 10^18 ThetaWei, 1 Gamma = 10^ TFuelWei
	//const thetaWeiToSend = new BigNumber(amount).multipliedBy(ten18);
	const thetaWeiToSend = amount;
	const tfuelWeiToSend = amountTFuel;
	//const feeInTFuelWei  = (new BigNumber(transactionFee)).multipliedBy(ten18); // Any fee >= 10^12 TFuelWei should work, higher fee yields higher priority
	const feeInTFuelWei  = transactionFee; // Any fee >= 10^12 TFuelWei should work, higher fee yields higher priority
	const senderAddr =  from;
	const receiverAddr = to;
	
	
	
	
	
    let response =await fetchSequence(senderAddr, {"network":"mainnet"});
	let responseJSON = response;
	let sequenceNum = parseInt(responseJSON['sequence']) + 1;
	const senderSequence = sequenceNum;
	
	
	const outputs = [
	{
                address: receiverAddr,
                thetaWei: thetaWeiToSend,
                tfuelWei: tfuelWeiToSend,
            }
        ];

    let tx =new SendTx(senderAddr, outputs, feeInTFuelWei, senderSequence);

    return tx;
    }
	
	
const isString=require('lodash/isString');
const isNumber=require('lodash/isNumber');
//const BigNumber=require('bignumber.js');
const Bytes = require('eth-lib/lib/bytes');
const RLP = require('eth-lib/lib/rlp');
const Hash = require('eth-lib/lib/hash');

class Tx{
    constructor(){

    }

    signBytes(chainID){

    }

    getType(){

    }

    rlpInput(){

    }
}

// /**
//  * Check if string is HEX, requires a 0x in front
//  *
//  * @method isHexStrict
//  *
//  * @param {String} hex to be checked
//  *
//  * @returns {Boolean}
//  */
const isHexStrict = (hex) => {
    return (isString(hex) || isNumber(hex)) && /^(-)?0x[0-9a-f]*$/i.test(hex);
};

/**
 * Convert a hex string to a byte array
 *
 * Note: Implementation from crypto-js
 *
 * @method hexToBytes
 *
 * @param {String} hex
 *
 * @returns {Array} the byte array
 */
const hexToBytes = (hex) => {
    hex = hex.toString(16);

    if (!isHexStrict(hex)) {
        throw new Error(`Given value "${hex}" is not a valid hex string.`);
    }

    hex = hex.replace(/^0x/i, '');
    hex = hex.length % 2 ? '0' + hex : hex;

    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }

    return bytes;
};

// Convert a byte array to a hex string
const bytesToHex = function(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
};

BigNumber.prototype.pad = function(size) {
    var s = String(this);
    while (s.length < (size || 2)) {s = "0" + s;}
    return s;
};

const bnFromString = str => {
    const base = str.slice(0, 2) === "0x" ? 16 : 10;
    const bigNum = new BigNumber(str, base);
    const bigNumWithPad = "0x" + bigNum.pad(2);
    return bigNumWithPad; // Jieyi: return "0x00" instead of "0x" to be compatible with the Golang/Java signature
};

const encodeWei = (wei) =>{
    if(wei === null || wei === undefined){
        return Bytes.fromNat("0x0");
    }
    else if(wei.isEqualTo(new BigNumber(0))){
        return Bytes.fromNat("0x0");
    }
    else{
        return Bytes.fromNumber(wei);
    }
};

class Coins{
    constructor(thetaWei, tfuelWei){
        this.thetaWei = thetaWei;
        this.tfuelWei = tfuelWei;
    }

    // encodeWei(wei){
    //     if(wei === null || wei === undefined){
    //         return Bytes.fromNat("0x0");
    //     }
    //     else if(wei.isEqualTo(new BigNumber(0))){
    //         return Bytes.fromNat("0x0");
    //     }
    //     else{
    //         return Bytes.fromNumber(wei);
    //     }
    // }

    rlpInput(){

        let rlpInput = [
            encodeWei(this.thetaWei),
            encodeWei(this.tfuelWei),
            //(this.thetaWei.isEqualTo(new BigNumber(0))) ? Bytes.fromNat("0x0") : Bytes.fromNumber(this.thetaWei),
            //(this.tfuelWei.isEqualTo(new BigNumber(0))) ? Bytes.fromNat("0x0") : Bytes.fromNumber(this.tfuelWei)
        ];

        return rlpInput;
    }
}

class TxInput{
    constructor(address, thetaWei, tfuelWei, sequence) {
        this.address = address;
        this.sequence = sequence;
        this.signature = "";

        if(thetaWei || tfuelWei){
            this.coins = new Coins(thetaWei, tfuelWei);
        }
        else{
            //TODO should this be undefined or null?
            this.coins = new Coins(null, null);
        }
    }

    setSignature(signature) {
        this.signature = signature;
    }

    rlpInput(){
        let address = null;

        if(this.address){
            address = this.address.toLowerCase();
        }
        else{
            address = Bytes.fromNat("0x0");
        }

        let rplInput = [
            address,
            this.coins.rlpInput(),
            Bytes.fromNumber(this.sequence),
            this.signature
        ];

        return rplInput;
    }
}

class TxOutput {
    constructor(address, thetaWei, tfuelWei) {
        this.address = address;

        if(thetaWei || tfuelWei){
            this.coins = new Coins(thetaWei, tfuelWei);
        }
        else{
            //TODO should this be undefined or null?
            this.coins = new Coins(null, null);
        }
    }

    rlpInput(){
        let address = null;

        if(this.address){
            address = this.address.toLowerCase();
        }
        else{
            //Empty address
            address = "0x0000000000000000000000000000000000000000";
        }

        let rplInput = [
            address,
            this.coins.rlpInput()
        ];

        return rplInput;
    }
}

const TxType = {
    TxTypeCoinbase: 0,
    TxTypeSlash: 1,
    TxTypeSend: 2,
    TxTypeReserveFund: 3,
    TxTypeReleaseFund: 4,
    TxTypeServicePayment: 5,
    TxTypeSplitRule: 6,
    TxTypeSmartContract: 7,
    TxTypeDepositStake: 8,
    TxTypeWithdrawStake: 9,
    TxTypeDepositStakeV2: 10,
};

class EthereumTx{
    constructor(payload){
        this.nonce = "0x0";
        this.gasPrice = "0x0";
        this.gas = "0x0";
        this.to = "0x0000000000000000000000000000000000000000";
        this.value = "0x0";
        this.input = payload;
    }
    
    rlpInput() {
        let rplInput= [
            Bytes.fromNat(this.nonce),
            Bytes.fromNat(this.gasPrice),
            Bytes.fromNat(this.gas),
            this.to.toLowerCase(),
            Bytes.fromNat(this.value),
            this.input,
        ];

        return rplInput;
    }
}

class SendTx extends Tx{
    constructor(senderAddr, outputs, feeInTFuelWei, senderSequence){
        super();

        let totalThetaWeiBN = new BigNumber(0);
        let totalTfuelWeiBN = new BigNumber(0);
        let feeInTFuelWeiBN = BigNumber.isBigNumber(feeInTFuelWei) ? feeInTFuelWei : (new BigNumber(feeInTFuelWei));

        for(var i = 0; i < outputs.length; i++){
            let output = outputs[i];
            let thetaWei = output.thetaWei;
            let tfuelWei = output.tfuelWei;

            let thetaWeiBN = BigNumber.isBigNumber(thetaWei) ? thetaWei : (new BigNumber(thetaWei));
            let tfuelWeiBN = BigNumber.isBigNumber(tfuelWei) ? tfuelWei : (new BigNumber(tfuelWei));

            totalThetaWeiBN = totalThetaWeiBN.plus(thetaWeiBN);
            totalTfuelWeiBN = totalTfuelWeiBN.plus(tfuelWeiBN);
        }

        this.fee = new Coins(new BigNumber(0), feeInTFuelWeiBN);

        let txInput = new TxInput(senderAddr, totalThetaWeiBN, totalTfuelWeiBN.plus(feeInTFuelWeiBN), senderSequence);
        this.inputs = [txInput];

        this.outputs = [];
        for(var j = 0; j < outputs.length; j++){
            let output = outputs[j];
            let address = output.address;
            let thetaWei = output.thetaWei;
            let tfuelWei = output.tfuelWei;

            let thetaWeiBN = BigNumber.isBigNumber(thetaWei) ? thetaWei : (new BigNumber(thetaWei));
            let tfuelWeiBN = BigNumber.isBigNumber(tfuelWei) ? tfuelWei : (new BigNumber(tfuelWei));

            let txOutput = new TxOutput(address, thetaWeiBN, tfuelWeiBN);

            this.outputs.push(txOutput);
        }
    }

    setSignature(signature){
        //TODO support multiple inputs
        let input = this.inputs[0];
        input.setSignature(signature);
    }

    signBytes(chainID){
        let sigz = [];
        //let input = this.inputs[0];

        // Detach the existing signatures from the input if any, so that we don't sign the signature
        //let originalSignature = input.signature;
        //input.signature = "";

        // Detach the existing signatures from the input if any, so that we don't sign the signature
        for(var i = 0; i < this.inputs.length; i++){
            let input = this.inputs[i];

            sigz[i] = input.signature;
            input.signature = "";
        }

        let encodedChainID = RLP.encode(Bytes.fromString(chainID));
        let encodedTxType = RLP.encode(Bytes.fromNumber(this.getType()));
        let encodedTx = RLP.encode(this.rlpInput());
        let payload = encodedChainID + encodedTxType.slice(2) + encodedTx.slice(2);

        // For ethereum tx compatibility, encode the tx as the payload
        let ethTxWrapper = new EthereumTx(payload);
        let signedBytes = RLP.encode(ethTxWrapper.rlpInput()); // the signBytes conforms to the Ethereum raw tx format

        console.log("SendTx :: signBytes :: txRawBytes = " + signedBytes);

        // Attach the original signature back to the inputs
        //input.signature = originalSignature;

        // Attach the original signature back to the inputs
        for(var j = 0; j < this.inputs.length; j++){
            let input = this.inputs[j];

            input.signature = sigz[j];
        }

        return signedBytes;
    }

    getType(){
        return TxType.TxTypeSend;
    }

    rlpInput(){
        let numInputs = this.inputs.length;
        let numOutputs = this.outputs.length;
        let inputBytesArray = [];
        let outputBytesArray = [];

        for(let i = 0; i < numInputs; i ++) {
            inputBytesArray[i] = this.inputs[i].rlpInput();
        }

        for (let i = 0; i < numOutputs; i ++) {
            outputBytesArray[i] = this.outputs[i].rlpInput();
        }

        let rlpInput = [
            this.fee.rlpInput(),
            inputBytesArray,
            outputBytesArray
        ];

        return rlpInput;
    }
}

const StakePurposes = {
    StakeForValidator: 0,
    StakeForGuardian: 1
};

class StakeTx extends Tx{

}

class DepositStakeTx extends StakeTx{
    constructor(source, holderAddress, stakeInThetaWei, feeInTFuelWei, purpose, senderSequence){
        super();

        let feeInTFuelWeiBN = BigNumber.isBigNumber(feeInTFuelWei) ? feeInTFuelWei : (new BigNumber(feeInTFuelWei));
        this.fee = new Coins(new BigNumber(0), feeInTFuelWeiBN);

        let stakeInThetaWeiBN = BigNumber.isBigNumber(stakeInThetaWei) ? stakeInThetaWei : (new BigNumber(stakeInThetaWei));
        this.source = new TxInput(source, stakeInThetaWeiBN, null, senderSequence);

        this.purpose = purpose;

        //Parse out the info from the holder (summary) param
        if(!holderAddress.startsWith('0x')){
            holderAddress = "0x" + holderAddress;
        }

        //Ensure correct size
        if(holderAddress.length !== 42) {
            //TODO: throw error
            console.log("Holder must be a valid address");
        }

        this.holder = new TxOutput(holderAddress, null, null);
    }

    setSignature(signature){
        let input = this.source;
        input.setSignature(signature);
    }

    signBytes(chainID){
        // Detach the existing signature from the source if any, so that we don't sign the signature
        let sig = this.source.signature;

        this.source.signature = "";

        let encodedChainID = RLP.encode(Bytes.fromString(chainID));
        let encodedTxType = RLP.encode(Bytes.fromNumber(this.getType()));
        let encodedTx = RLP.encode(this.rlpInput());
        let payload = encodedChainID + encodedTxType.slice(2) + encodedTx.slice(2);

        // For ethereum tx compatibility, encode the tx as the payload
        let ethTxWrapper = new EthereumTx(payload);
        let signedBytes = RLP.encode(ethTxWrapper.rlpInput()); // the signBytes conforms to the Ethereum raw tx format

        // Attach the original signature back to the source
        this.source.signature = sig;

        return signedBytes;
    }

    getType(){
        return TxType.TxTypeDepositStake;
    }

    rlpInput(){
        let rlpInput = [
            this.fee.rlpInput(),
            this.source.rlpInput(),
            this.holder.rlpInput(),

            (this.purpose === 0 ? Bytes.fromNat("0x0") : Bytes.fromNumber(this.purpose)),
        ];

        return rlpInput;
    }
}

class DepositStakeV2Tx extends StakeTx{
    constructor(source, holderSummary, stakeInThetaWei, feeInTFuelWei, purpose, senderSequence){
        super();

        let feeInTFuelWeiBN = BigNumber.isBigNumber(feeInTFuelWei) ? feeInTFuelWei : (new BigNumber(feeInTFuelWei));
        this.fee = new Coins(new BigNumber(0), feeInTFuelWeiBN);

        let stakeInThetaWeiBN = BigNumber.isBigNumber(stakeInThetaWei) ? stakeInThetaWei : (new BigNumber(stakeInThetaWei));
        this.source = new TxInput(source, stakeInThetaWeiBN, null, senderSequence);

        this.purpose = purpose;


        console.log("BEFORE :: holderSummary == " );
        console.log(holderSummary);

        //Parse out the info from the holder (summary) param
        if(!holderSummary.startsWith('0x')){
            holderSummary = "0x" + holderSummary;
        }

        console.log("AFTER :: holderSummary == " );
        console.log(holderSummary);

        //Ensure correct size
        if(holderSummary.length !== 460) {
            //TODO: throw error
            console.log("Holder must be a valid guardian address");
        }

        //let guardianKeyBytes = Bytes.fromString(holderSummary);
        let guardianKeyBytes = Bytes.toArray(holderSummary);

        console.log("guardianKeyBytes == " );
        //console.log(guardianKeyBytes);
        console.log(typeof guardianKeyBytes);

        //slice instead of subarray
        let holderAddressBytes = guardianKeyBytes.slice(0, 20);

        this.blsPubkeyBytes = guardianKeyBytes.slice(20, 68);
        this.blsPopBytes = guardianKeyBytes.slice(68, 164);
        this.holderSigBytes = guardianKeyBytes.slice(164);

        let holderAddress = Bytes.fromArray(holderAddressBytes);

        console.log("holderAddress == ");
        console.log(holderAddress);

        this.holder = new TxOutput(holderAddress, null, null);
    }

    setSignature(signature){
        console.log("setSignature :: signature == " + signature);

        let input = this.source;
        input.setSignature(signature);
    }

    signBytes(chainID){
        console.log("DepositStakeTx :: signBytes :: chainId == " + chainID);

        console.log("DepositStakeTx :: signBytes :: this.source == " + this.source);

        console.log("DepositStakeTx :: signBytes :: this.source.signature == " + this.source.signature);

        // Detach the existing signature from the source if any, so that we don't sign the signature
        let sig = this.source.signature;

        console.log("DepositStakeTx :: signBytes :: sig == '" + sig + "'");
        console.log("DepositStakeTx :: signBytes :: sig type == " + typeof sig);


        this.source.signature = "";

        let encodedChainID = RLP.encode(Bytes.fromString(chainID));
        let encodedTxType = RLP.encode(Bytes.fromNumber(this.getType()));
        let encodedTx = RLP.encode(this.rlpInput());
        let payload = encodedChainID + encodedTxType.slice(2) + encodedTx.slice(2);

        // For ethereum tx compatibility, encode the tx as the payload
        let ethTxWrapper = new EthereumTx(payload);
        let signedBytes = RLP.encode(ethTxWrapper.rlpInput()); // the signBytes conforms to the Ethereum raw tx format

        console.log("SendTx :: signBytes :: txRawBytes = " + signedBytes);

        // Attach the original signature back to the source
        this.source.signature = sig;

        return signedBytes;
    }

    getType(){
        return TxType.TxTypeDepositStakeV2;
    }

    rlpInput(){
        let rlpInput = [
            this.fee.rlpInput(),
            this.source.rlpInput(),
            this.holder.rlpInput(),

            Bytes.fromNumber(this.purpose),

            Bytes.fromArray(this.blsPubkeyBytes),
            Bytes.fromArray(this.blsPopBytes),
            Bytes.fromArray(this.holderSigBytes)
        ];

        return rlpInput;
    }
}

class WithdrawStakeTx extends StakeTx{
    constructor(source, holder, feeInTFuelWei, purpose, senderSequence){
        super();

        let feeInTFuelWeiBN = BigNumber.isBigNumber(feeInTFuelWei) ? feeInTFuelWei : (new BigNumber(feeInTFuelWei));
        this.fee = new Coins(new BigNumber(0), feeInTFuelWeiBN);

        this.source = new TxInput(source, null, null, senderSequence);

        this.holder = new TxOutput(holder, null, null);

        this.purpose = purpose;
    }

    setSignature(signature){
        let input = this.source;
        input.setSignature(signature);
    }

    signBytes(chainID){
        // Detach the existing signature from the source if any, so that we don't sign the signature
        let sig = this.source.signature;
        this.source.signature = "";

        let encodedChainID = RLP.encode(Bytes.fromString(chainID));
        let encodedTxType = RLP.encode(Bytes.fromNumber(this.getType()));
        let encodedTx = RLP.encode(this.rlpInput());
        let payload = encodedChainID + encodedTxType.slice(2) + encodedTx.slice(2);

        // For ethereum tx compatibility, encode the tx as the payload
        let ethTxWrapper = new EthereumTx(payload);
        let signedBytes = RLP.encode(ethTxWrapper.rlpInput()); // the signBytes conforms to the Ethereum raw tx format

        console.log("SendTx :: signBytes :: txRawBytes = " + signedBytes);

        // Attach the original signature back to the source
        this.source.signature = sig;

        return signedBytes;
    }

    getType(){
        return TxType.TxTypeWithdrawStake;
    }

    rlpInput(){
        let rlpInput = [
            this.fee.rlpInput(),
            this.source.rlpInput(),
            this.holder.rlpInput(),

            (this.purpose === 0 ? Bytes.fromNat("0x0") : Bytes.fromNumber(this.purpose)),
        ];

        return rlpInput;
    }
}

//const elliptic = (window.elliptic || require("elliptic"));
const elliptic = require("elliptic");
const secp256k1 = new elliptic.ec("secp256k1"); // eslint-disable-line
const SHA3_NULL_S = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';

const sha3 = (value) => {
    if (isHexStrict(value) && /^0x/i.test(value.toString())) {
        value = hexToBytes(value);
    }

    const returnValue = Hash.keccak256(value); // jshint ignore:line

    if (returnValue === SHA3_NULL_S) {
        return null;
    } else {
        return returnValue;
    }
};

const encodeSignature = ([v, r, s]) => Bytes.flatten([r, s, v]);

const makeSigner = addToV => (hash, privateKey) => {
  const ecKey = secp256k1.keyFromPrivate(new Buffer(privateKey.slice(2), "hex"));
  console.log("eckey")
  console.log(hash)
  const signature = ecKey.sign(new Buffer(hash.slice(2), "hex"), { canonical: true });
  console.log(signature)
  console.log("signature info")
  console.log(encodeSignature([
      bnFromString(Bytes.fromNumber(addToV + signature.recoveryParam)), 
      Bytes.pad(32, Bytes.fromNat("0x" + signature.r.toString(16))), 
      Bytes.pad(32, Bytes.fromNat("0x" + signature.s.toString(16)))
    ]))
  return encodeSignature([
      bnFromString(Bytes.fromNumber(addToV + signature.recoveryParam)), 
      Bytes.pad(32, Bytes.fromNat("0x" + signature.r.toString(16))), 
      Bytes.pad(32, Bytes.fromNat("0x" + signature.s.toString(16)))
    ]);
};

const sign = makeSigner(0);

class TxSigner {

    static signAndSerializeTx(chainID, tx, privateKey) {
        let signedTx = this.signTx(chainID, tx, privateKey);
        let signedRawBytes = this.serializeTx(signedTx);

        return signedRawBytes;
    }

    static signTx(chainID, tx, privateKey) {
        let txRawBytes = tx.signBytes(chainID);
		console.log(tx)
		console.log(txRawBytes)
        let txHash = sha3(txRawBytes);
        let signature = sign(txHash, privateKey);
        tx.setSignature(signature);
		console.log("signed info -----------")
		console.log(tx)

        return tx
    }
	static signTxtohash(chainID, tx) {
        let txRawBytes = tx.signBytes(chainID);
        let txHash = sha3(txRawBytes);

        return txHash
    }

    static serializeTx(tx) {
        let encodedTxType = RLP.encode(Bytes.fromNumber(tx.getType()));
        let encodedTx = RLP.encode(tx.rlpInput());// this time encode with signature
        let signedRawBytes = encodedTxType + encodedTx.slice(2);
		let txidInfo = sha3(signedRawBytes);
		console.log("txidinfo---",txidInfo)

        return signedRawBytes;
    }
}

var Web3Utils = require('web3-utils');

class SmartContractTx extends Tx{
    constructor(fromAddress, toAddress, gasLimit, gasPrice, data, value, senderSequence){
        super();

        let valueWeiBN = BigNumber.isBigNumber(value) ? value : (new BigNumber(value));

        this.from = new TxInput(fromAddress, null, valueWeiBN, senderSequence);
        this.to = new TxOutput(toAddress, null, null);

        this.gasLimit = gasLimit;
        this.gasPrice = gasPrice;

        if(data.toLowerCase().startsWith("0x") === false){
            data = "0x" + data;
        }

        this.data = Bytes.toArray(data);
    }

    setSignature(signature){
        let input = this.from;
        input.setSignature(signature);
    }

    signBytes(chainID){
        // Detach the existing signature from the source if any, so that we don't sign the signature
        let sig = this.from.signature;

        this.from.signature = "";

        let encodedChainID = RLP.encode(Bytes.fromString(chainID));
        let encodedTxType = RLP.encode(Bytes.fromNumber(this.getType()));
        let encodedTx = RLP.encode(this.rlpInput());
        let payload = encodedChainID + encodedTxType.slice(2) + encodedTx.slice(2);

        // For ethereum tx compatibility, encode the tx as the payload
        let ethTxWrapper = new EthereumTx(payload);
        let signedBytes = RLP.encode(ethTxWrapper.rlpInput()); // the signBytes conforms to the Ethereum raw tx format

        // Attach the original signature back to the source
        this.from.signature = sig;

        return signedBytes;
    }

    getType(){
        return TxType.TxTypeSmartContract;
    }

    rlpInput(){
        let rlpInput = [
            this.from.rlpInput(),
            this.to.rlpInput(),

            Bytes.fromNumber(this.gasLimit),
            encodeWei(this.gasPrice),

            Bytes.fromArray(this.data)
        ];

        return rlpInput;
    }
}

var index = {
    SendTx,
    DepositStakeTx: DepositStakeTx,
    DepositStakeV2Tx: DepositStakeV2Tx,
    WithdrawStakeTx,
    SmartContractTx,
    TxSigner,
    StakePurposes,
    Utils: {
        hexToBytes,
        bytesToHex
    }
};

