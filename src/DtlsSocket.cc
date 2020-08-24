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

	Nan::Set(
		target,
		Nan::New("DtlsSocket").ToLocalChecked(),
		Nan::GetFunction(ctor).ToLocalChecked()
	);
}

void DtlsSocket::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
	size_t priv_key_len = !info[0]->IsNullOrUndefined() ? Buffer::Length(info[0]) : 0;
	size_t peer_pub_key_len = !info[1]->IsNullOrUndefined() ? Buffer::Length(info[1]) : 0;
	size_t psk_len = !info[2]->IsNullOrUndefined() ? Buffer::Length(info[2]) : 0;
	size_t psk_identity_len = !info[3]->IsNullOrUndefined() ? Buffer::Length(info[3]) : 0;

	const unsigned char *priv_key = !info[0]->IsNullOrUndefined() ? (const unsigned char *)Buffer::Data(info[0]) : NULL;
	const unsigned char *peer_pub_key =  !info[1]->IsNullOrUndefined() ? (const unsigned char *)Buffer::Data(info[2]) : NULL;
	const unsigned char *psk = !info[2]->IsNullOrUndefined() ? (const unsigned char *)Buffer::Data(info[2]) : NULL;
	const unsigned char *psk_identity = !info[3]->IsNullOrUndefined() ? (const unsigned char *)Buffer::Data(info[3]) : NULL;

	Nan::Callback* send_cb = new Nan::Callback(info[4].As<v8::Function>());
	Nan::Callback* hs_cb = new Nan::Callback(info[5].As<v8::Function>());
	Nan::Callback* error_cb = new Nan::Callback(info[6].As<v8::Function>());

	int debug_level = 0;
	if (info.Length() > 7) {
		v8::Maybe<uint32_t> debug_level_maybe = info[7]->Uint32Value(Nan::GetCurrentContext());
		if (debug_level_maybe.IsJust()) {
			debug_level = debug_level_maybe.FromJust();
		}
	}

	DtlsSocket *socket = new DtlsSocket(
		priv_key, priv_key_len,
		peer_pub_key, peer_pub_key_len,
		psk, psk_len,
		psk_identity, psk_identity_len,
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
	int ret = socket->close();
	if (ret < 0) {
		// TODO error?
		return;
	}

	info.GetReturnValue().Set(Nan::New(ret));
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

DtlsSocket::DtlsSocket(const unsigned char *priv_key,
											 size_t priv_key_len,
											 const unsigned char *peer_pub_key,
											 size_t peer_pub_key_len,
											 const unsigned char *psk,
											 size_t psk_len,
											 const unsigned char *psk_identity,
											 size_t psk_identity_len,
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

	recv_len = 0;
	recv_buf = NULL;

	mbedtls_ssl_init(&ssl_context);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&clicert);
	mbedtls_pk_init(&pkey);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(debug_level);
#endif

	if(priv_key != NULL) {
		ret = mbedtls_pk_parse_key(&pkey,
															(const unsigned char *)priv_key,
															priv_key_len,
															NULL,
															0);
		if (ret != 0) goto exit;
	}

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
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_2);

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if(priv_key != NULL) {
		ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
		if (ret != 0) goto exit;
	} else if(psk != NULL) {
		ret = mbedtls_ssl_conf_psk(&conf, psk, psk_len, psk_identity, psk_identity_len);
		if (ret != 0) goto exit;
	}

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	static int ssl_cert_types[] = { MBEDTLS_TLS_CERT_TYPE_RAW_PUBLIC_KEY, MBEDTLS_TLS_CERT_TYPE_NONE };
	mbedtls_ssl_conf_client_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_server_certificate_types(&conf, ssl_cert_types);
	mbedtls_ssl_conf_certificate_receive(&conf, MBEDTLS_SSL_RECEIVE_CERTIFICATE_DISABLED);

	if((ret = mbedtls_ssl_setup(&ssl_context, &conf)) != 0) goto exit;

	if(peer_pub_key != NULL) {
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
	}

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
	v8::Local<v8::Function> sendCallbackDirect = send_cb->GetFunction();
	Nan::Call(
		sendCallbackDirect,
		Nan::GetCurrentContext()->Global(),
		1,
		argv
	);
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
	if (ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake(&ssl_context);
		switch (ret) {
			case 0:
				break;
			case MBEDTLS_ERR_SSL_WANT_READ:
			case MBEDTLS_ERR_SSL_WANT_WRITE:
				return ret;
			default:
				// bad things
				error(ret);
				return 0;
		}
	}

	// this should only be called once when we first finish the handshake
	v8::Local<v8::Function> handshakeCallbackDirect = handshake_cb->GetFunction();
	Nan::Call(
		handshakeCallbackDirect,
		Nan::GetCurrentContext()->Global(),
		0,
		NULL
	);
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
	v8::Local<v8::Function> errorCallbackDirect = error_cb->GetFunction();
	Nan::Call(
		errorCallbackDirect,
		Nan::GetCurrentContext()->Global(),
		2,
		argv
	);
}

void DtlsSocket::store_data(const unsigned char *buf, size_t len) {
	recv_buf = buf;
	recv_len = len;
}

int DtlsSocket::close() {
	if(ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		return 1;
	}
	return mbedtls_ssl_close_notify(&ssl_context);
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
