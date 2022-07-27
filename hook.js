
console.log('hooked');
 


function startTLSKeyLogger(SSL_CTX_new, SSL_CTX_set_keylog_callback) {
    console.log("start----")
    function keyLogger(ssl, line) {
        console.log(new NativePointer(line).readCString());
    }
    const keyLogCallback = new NativeCallback(keyLogger, 'void', ['pointer', 'pointer']);

    Interceptor.attach(SSL_CTX_new, {
        onLeave: function(retval) {
            const ssl = new NativePointer(retval);
            const SSL_CTX_set_keylog_callbackFn = new NativeFunction(SSL_CTX_set_keylog_callback, 'void', ['pointer', 'pointer']);
            SSL_CTX_set_keylog_callbackFn(ssl, keyLogCallback);
        }
    });
}


var boringsslFrameWork = Module.getBaseAddress("boringssl")
console.log('boringsslFrameWork: ' + boringsslFrameWork);
var SSL_WRITE = boringsslFrameWork.add(0x1A3F4);
var SSL_READ = boringsslFrameWork.add(0x1A15C);
var SSL_CTX_new = boringsslFrameWork.add(0x1934C);
var SSL_CTX_set_keylog_callback = boringsslFrameWork.add(0x1c17c);
startTLSKeyLogger(
    SSL_CTX_new,
    SSL_CTX_set_keylog_callback
)

if (SSL_WRITE) {
    Interceptor.attach(SSL_WRITE, {
        onEnter: function (args) {
            this.ssl = args[0].toString();
            this.buf = ptr(args[1]);
        },
        onLeave: function (retval) {
            const len = retval.toInt32();
            if (len > 0) {
                console.log('SSL_write\n', this.buf.readByteArray(len), '\n', '*'.repeat(120));
//                send({
//                    code: 100,
//                    ssl: this.ssl
//                }, this.buf.readByteArray(len));
            }
        }
    });
}
 
if (SSL_READ) {
    Interceptor.attach(SSL_READ, {
        onEnter: function (args) {
            this.ssl = args[0].toString();
            this.buf = ptr(args[1]);
        },
        onLeave: function (retval) {
            const len = retval.toInt32();
            if (len > 0) {
                console.log('SSL_read\n', this.buf.readByteArray(len), '\n', '*'.repeat(120));
 
//                send({
//                    code: 200,
//                    ssl: this.ssl
//                }, this.buf.readByteArray(len));
            }
        }
    });
}
