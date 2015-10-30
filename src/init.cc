
#include "DtlsSocket.h"

NAN_MODULE_INIT(init) {
	DtlsSocket::Initialize(target);
}

NODE_MODULE(node_mbed_dtls_client, init);
