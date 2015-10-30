#include "DtlsSocket.h"

#include <stdlib.h>

#include "mbedtls/error.h"

#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

using namespace node;

static void my_debug( void *ctx, int level,
											const char *file, int line,
											const char *str )
{
	((void) level);

	mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *) ctx);
}

Nan::Persistent<v8::FunctionTemplate> DtlsSocket::constructor;

void
DtlsSocket::Initialize(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE target) {
	Nan::HandleScope scope;

	// Constructor
	v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(DtlsSocket::New);
	constructor.Reset(ctor);
	v8::Local<v8::ObjectTemplate>	ctorInst = ctor->InstanceTemplate();
	ctorInst->SetInternalFieldCount(1);
	ctor->SetClassName(Nan::New("DtlsSocket").ToLocalChecked());

	Nan::SetPrototypeMethod(ctor, "receiveData", ReceiveDataFromNode);
	Nan::SetPrototypeMethod(ctor, "close", Close);
	Nan::SetPrototypeMethod(ctor, "send", Send);
	Nan::SetPrototypeMethod(ctor, "connect", Connect);
	
	Nan::Set(target, Nan::New("DtlsSocket").ToLocalChecked(), ctor->GetFunction());
}

void DtlsSocket::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	
	size_t pub_key_len = Buffer::Length(info[0]);
	size_t priv_key_len = Buffer::Length(info[1]);
	size_t peer_pub_key_len = Buffer::Length(info[2]);

	const unsigned char *pub_key = (const unsigned char *)Buffer::Data(info[0]);
	const unsigned char *priv_key = (const unsigned char *)Buffer::Data(info[1]);
	const unsigned char *peer_pub_key = (const unsigned char *)Buffer::Data(info[2]);

	Nan::Callback* send_cb = new Nan::Callback(info[3].As<v8::Function>());
	Nan::Callback* hs_cb = new Nan::Callback(info[4].As<v8::Function>());
	Nan::Callback* error_cb = new Nan::Callback(info[5].As<v8::Function>());

	int debug_level = 0;
	if (info.Length() > 6) {
		debug_level = info[6]->Uint32Value();
	}

	DtlsSocket *socket = new DtlsSocket(
		pub_key, pub_key_len,
		priv_key, priv_key_len,
		peer_pub_key, peer_pub_key_len,
		send_cb, hs_cb, error_cb,
		debug_level);
	socket->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

void DtlsSocket::ReceiveDataFromNode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	const unsigned char *recv_data = (const unsigned char *)Buffer::Data(info[0]);
	socket->store_data(recv_data, Buffer::Length(info[0]));

	int len = 1024;
	unsigned char buf[len];	
	len = socket->receive_data(buf, len);

	if (len > 0) {
		info.GetReturnValue().Set(Nan::CopyBuffer((char*)buf, len).ToLocalChecked());
	}
}

void DtlsSocket::Close(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	socket->close();
}

void DtlsSocket::Send(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	
	const unsigned char *send_data = (const unsigned char *)Buffer::Data(info[0]);
	socket->send(send_data, Buffer::Length(info[0]));
}

void DtlsSocket::Connect(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	DtlsSocket *socket = Nan::ObjectWrap::Unwrap<DtlsSocket>(info.This());
	socket->step();
}

int net_send( void *ctx, const unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->send_encrypted(buf, len);
}

int net_recv( void *ctx, unsigned char *buf, size_t len ) {
	DtlsSocket* socket = (DtlsSocket*)ctx;
	return socket->recv(buf, len);
}

DtlsSocket::DtlsSocket(const unsigned char *pub_key,
											 size_t pub_key_len,
											 const unsigned char *priv_key,
											 size_t priv_key_len,
											 const unsigned char *peer_pub_key,
											 size_t peer_pub_key_len,
											 Nan::Callback* send_callback,
											 Nan::Callback* hs_callback,
											 Nan::Callback* error_callback,
											 int debug_level)
		: Nan::ObjectWrap(),
		send_cb(send_callback),
		error_cb(error_callback),
		handshake_cb(hs_callback) {
	int ret;
	const char *pers = "dtls_client";

	mbedtls_ssl_init(&ssl_context);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&clicert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(debug_level);
#endif

	ret = mbedtls_pk_parse_public_key(&pkey,
																		(const unsigned char *)pub_key,
																		pub_key_len);
	if (ret != 0) goto exit;
	
	ret = mbedtls_pk_parse_key(&pkey,
														 (const unsigned char *)priv_key,
														 priv_key_len,
														 NULL,
														 0);
	if (ret != 0) goto exit;

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
															mbedtls_entropy_func,
															&entropy,
															(const unsigned char *) pers,
															strlen(pers));
	if (ret != 0) goto exit;

	ret = mbedtls_ssl_config_defaults(&conf,
																		MBEDTLS_SSL_IS_CLIENT,
																		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
																		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) goto exit;
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
	if (ret != 0) goto exit;

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	static int ssl_cert_types[] = { MBEDTLS_TLS_CERT_TYPE_RAW_PUBLIC_KEY, MBEDTLS_TLS_CERT_TYPE_NONE };
	mbedtls_ssl_conf_client_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_server_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_certificate_receive(&conf, MBEDTLS_SSL_RECEIVE_CERTIFICATE_DISABLED);

	if((ret = mbedtls_ssl_setup(&ssl_context, &conf)) != 0) goto exit;

	
	if((ssl_context.session_negotiate->peer_cert = (mbedtls_x509_crt*)calloc(1,
										sizeof(mbedtls_x509_crt))) == NULL)
	{
			ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
			goto exit;
	}
	mbedtls_x509_crt_init(ssl_context.session_negotiate->peer_cert);
	ret = mbedtls_pk_parse_public_key(&ssl_context.session_negotiate->peer_cert->pk,
																		(const unsigned char *)peer_pub_key,
																		peer_pub_key_len);
	if (ret != 0) goto exit;

	mbedtls_ssl_set_timer_cb(&ssl_context,
													 &timer,
													 mbedtls_timing_set_delay,
													 mbedtls_timing_get_delay);
	mbedtls_ssl_set_bio(&ssl_context, this, net_send, net_recv, NULL);

	return;
exit:
	throwError(ret);
	return;
}

int DtlsSocket::send_encrypted(const unsigned char *buf, size_t len) {
	v8::Local<v8::Value> argv[] = {
		Nan::CopyBuffer((char *)buf, len).ToLocalChecked()
	};
	send_cb->Call(1, argv);
	return len;
}

int DtlsSocket::recv(unsigned char *buf, size_t len) {
	if (recv_len != 0) {
		len = recv_len;
		memcpy(buf, recv_buf, recv_len);
		recv_buf = NULL;
		recv_len = 0;
		return len;
	}

	return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsSocket::send(const unsigned char *buf, size_t len) {
	int ret;
	ret = mbedtls_ssl_write(&ssl_context, buf, len);
	if (ret < 0)
	{
		error(ret);
		return ret;
	}
	len = ret;
	return ret;
}

int DtlsSocket::receive_data(unsigned char *buf, int len) {
	int ret;

	if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
		// normal reading of unencrypted data	
		memset(buf, 0, len);
		ret = mbedtls_ssl_read(&ssl_context, buf, len);
		if (ret <= 0) {
			error(ret);
			return 0;
		}
		return ret;
	}

	return step();
}

int DtlsSocket::step() {
	int ret;
	// handshake
	while (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl_context);
		if (ret == 0) {
			// in these states we are waiting for more input
			if (
				ssl_context.state == MBEDTLS_SSL_SERVER_HELLO ||
				ssl_context.state == MBEDTLS_SSL_SERVER_KEY_EXCHANGE ||
				ssl_context.state == MBEDTLS_SSL_CERTIFICATE_REQUEST ||
				ssl_context.state == MBEDTLS_SSL_SERVER_HELLO_DONE ||
				ssl_context.state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC ||
				ssl_context.state == MBEDTLS_SSL_SERVER_FINISHED
				) {
				return 0;
			}
			// keep looping to send everything
			continue;
		}
		// else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
		// 	// client will start a new session, so reset things
		// 	reset();
		// 	continue;
		// }
		else if (ret != 0) {
			// bad things
			error(ret);			
			return 0;
		}
	}

	// this should only be called once when we first finish the handshake
	handshake_cb->Call(0, NULL);
	return 0;
}

void DtlsSocket::throwError(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	Nan::ThrowError(error_buf);
}

void DtlsSocket::error(int ret) {
	char error_buf[100];
	mbedtls_strerror(ret, error_buf, 100);
	v8::Local<v8::Value> argv[] = {
		Nan::New(ret),
		Nan::New(error_buf).ToLocalChecked()
	};
	error_cb->Call(2, argv);
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
	recv_buf = buf;
	recv_len = len;
}

void DtlsSocket::close() {
	mbedtls_ssl_close_notify(&ssl_context);
}

DtlsSocket::~DtlsSocket() {
	delete send_cb;
	send_cb = nullptr;
	delete error_cb;
	error_cb = nullptr;
	delete handshake_cb;
	handshake_cb = nullptr;
	recv_buf = nullptr;
	mbedtls_x509_crt_free(&clicert);
	mbedtls_pk_free(&pkey);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_ssl_free(&ssl_context);
}
