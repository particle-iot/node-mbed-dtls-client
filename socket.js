'use strict';

const stream = require('stream');
const dgram = require('dgram');
const fs = require('fs');

const mbed = require('./build/Release/node_mbed_dtls_client');

const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;

class DtlsSocket extends stream.Duplex {
	constructor(options) {
		super({ allowHalfOpen: false });
		options = options || {};

		this.remoteAddress = options.host;
		this.remotePort = options.port;
		this.dgramSocket = options.socket || dgram.createSocket('udp4');

		this._onMessage = this._onMessage.bind(this);
		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._end();
		});
		this.dgramSocket.once('close', () => {
			this._end();
		});

		const publicKey = Buffer.isBuffer(options.cert) ? options.cert : fs.readFileSync(options.cert);
		const privateKey = Buffer.isBuffer(options.key) ? options.key : fs.readFileSync(options.key);
		const peerPublicKey = Buffer.isBuffer(options.peerPublicKey) ? options.peerPublicKey : fs.readFileSync(options.peerPublicKey);

		this.mbedSocket = new mbed.DtlsSocket(publicKey, privateKey, peerPublicKey,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this),
			options.debug);

		process.nextTick(() => {
			this.mbedSocket.connect();
		});
	}

	address() {
		return this.dgramSocket.address();
	}

	_onMessage(msg) {
		if (!this.mbedSocket) {
			return;
		}

		const data = this.mbedSocket.receiveData(msg);
		if (data) {
			this.push(data);
		}
	}

	_read() {
		// do nothing!
	}

	_write(chunk, encoding, callback) {
		this._sendCallback = callback;
		this.mbedSocket.send(chunk);
	}

	_sendEncrypted(msg) {
		if (!this.dgramSocket || !this.dgramSocket._handle) {
			if (this._sendCallback) {
				this._sendCallback(new Error('no underlying socket'));
				this._sendCallback = null;
			}
			return;
		}
		this.dgramSocket.send(msg, 0, msg.length, this.remotePort, this.remoteAddress, err => {
			if (this._sendCallback) {
				this._sendCallback(err);
				this._sendCallback = null;
			}
		});
	}

	_handshakeComplete() {
		this.connected = true;
		this.emit('secureConnect', this);
	}

	_error(code, msg) {
		if (code === MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			this._end();
			return;
		}

		this._hadError = true;
		this.emit('error', code, msg);
		this._end();
	}

	end() {
		this._clientEnd = true;
		this._end();
	}

	_end() {
		this.dgramSocket.removeListener('message', this._onMessage);
		super.end();
		this.push(null);
		this.mbedSocket.close();
		this.mbedSocket = null;
		if (!this._clientEnd) {
			this._finishEnd();
		}
	}

	_finishEnd() {
		this.dgramSocket.close();
		this.dgramSocket = null;
		this.emit('close', this._hadError);
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
