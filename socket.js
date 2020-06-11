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
		if(options.socket) {
			this.dgramSocket = options.socket;
			this.dontCloseDgramSocket = true;
		} else {
			this.dgramSocket = dgram.createSocket('udp4');
			this.dontCloseDgramSocket = false;
		}

		this._onMessage = this._onMessage.bind(this);
		this.dgramSocket.on('message', this._onMessage);
		this.dgramSocket.once('error', err => {
			this.emit('error', err);
			this._end();
		});
		this.dgramSocket.once('close', () => {
			this._socketClosed();
		});

		const privateKey = (Buffer.isBuffer(options.key) || options.key === undefined) ? options.key : fs.readFileSync(options.key);
		const peerPublicKey = (Buffer.isBuffer(options.peerPublicKey) || options.peerPublicKey === undefined) ? options.peerPublicKey : fs.readFileSync(options.peerPublicKey);
		const psk = (Buffer.isBuffer(options.psk) || options.psk === undefined) ? options.psk : fs.readFileSync(options.psk);
		const pskIdentity = (Buffer.isBuffer(options.pskIdentity) || options.pskIdentity === undefined) ? options.pskIdentity : fs.readFileSync(options.pskIdentity);

		this.mbedSocket = new mbed.DtlsSocket(privateKey, peerPublicKey,
			psk, pskIdentity,
			this._sendEncrypted.bind(this),
			this._handshakeComplete.bind(this),
			this._error.bind(this),
			options.debug);

		process.nextTick(() => {
			this.mbedSocket.connect();
		});
	}

	bind(port, address, callback) {
		this.dgramSocket.bind(port, address, callback);
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
		if (!this.mbedSocket) {
			callback(new Error('Cannot write to socket that no longer exists.'));
			return;
		}

		this._sendCallback = callback;
		this.mbedSocket.send(chunk);
	}

	_sendEncrypted(msg) {
		// store the callback here because '_write' might be called
		// again before the underlying socket finishes sending
		const sendCb = this._sendCallback;
		this._sendCallback = null;
		const sendFinished = (err) => {
			if (sendCb) {
				sendCb(err);
			}
			if (this._sendNotify) {
				this._closeSocket();
			}
		};

		if (!this.dgramSocket || !this.dgramSocket._handle) {
			process.nextTick(() => {
				sendFinished(new Error('no underlying socket'));
			});
			return;
		}

		this.dgramSocket.send(msg, 0, msg.length, this.remotePort, this.remoteAddress, sendFinished);
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
		if (this._sendCallback) {
			this._sendCallback(code);
			this._sendCallback = null;
		} else {
			this.emit('error', code, msg);
		}
		this._end();
	}

	end() {
		this._sendNotify = true;
		this._end();
	}

	_end() {
		if (this._ending) {
			return;
		}
		this._ending = true;

		if (this.dgramSocket) {
			this.dgramSocket.removeListener('message', this._onMessage);
		}

		super.end();
		this.push(null);

		const noSend = this.mbedSocket.close();
		this.mbedSocket = null;

		if (noSend || !this._sendNotify) {
			this._closeSocket();
		}
	}

	_closeSocket() {
		if (!this.dgramSocket) {
			this._socketClosed();
			return;
		}

		// Only close the dgramSocket if we generated it.
		if(!this.dontCloseDgramSocket) {
			this.dgramSocket.close();
		}

		this.emit('close', this._hadError);
	}

	_socketClosed() {
		this.dgramSocket = null;
		this.emit('close', this._hadError);
		this.removeAllListeners();
	}
}

module.exports = DtlsSocket;
