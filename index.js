'use strict';

const DtlsSocket = require('./socket');

function connect(options, callback) {
	const socket = new DtlsSocket(options);
	if (callback) {
		socket.once('secureConnect', callback);
	}

	return socket;
}

module.exports = { connect };
