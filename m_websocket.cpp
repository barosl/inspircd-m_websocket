#include "inspircd.h"
#include "sha1.h"

#define SHA1_LEN 20

#if INSPIRCD_VERSION_MAJ >= 202

#define USE_IO_HOOK_PROVIDER

#define SE_Send SocketEngine::Send
#define SE_Recv SocketEngine::Recv

#define log(x) ServerInstance->Logs->Log(MODNAME, LOG_DEFAULT, (x))

#else

#define SE_Send ServerInstance->SE->Send
#define SE_Recv ServerInstance->SE->Recv
#define SE_GetMaxFds ServerInstance->SE->GetMaxFds

#define LOG_DEFAULT DEFAULT
#define log(x) ServerInstance->Logs->Log("m_websocket", LOG_DEFAULT, "m_websocket: " x)

#endif

class WebSocketFrame {
public:
    static std::string Pack(const std::string &buf) {
        std::string res;

        if (buf.length() < 126) {
            res += (char)0x81;
            res += buf.length();
            res += buf;

        } else if (buf.length() < 0x10000) {
            res += (char)0x81;
            res += (char)126;
            res += buf.length() >> 8;
            res += buf.length() & 0xff;
            res += buf;

        } else {
            /* FIXME */
        }

        return res;
    }

    static void Unmask(std::string &buf, const char *mask_key) {
        for (int i=0;i<(int)buf.length();i++) {
            buf[i] ^= mask_key[i % 4];
        }
    }

    static std::string Unpack(const std::string &frame) {
        const unsigned char *buf = (unsigned char*)frame.data();
        int buf_len = frame.size();
        int buf_offset = 0;

        if (buf_len < buf_offset + 2) return "";

        int fin = buf[buf_offset] & 0x80;
        int op = buf[buf_offset] & 0xf;
        int mask = buf[buf_offset+1] & 0x80;
        int plen = buf[buf_offset+1] & 0x7f;

        buf_offset += 2;

        if (!fin) {
            /* TODO */
            log("WebSocketFrame::Unpack(): Fragmented messages are not supported");
            return "";
        }

        if (op < 3) {
            if (plen == 126) {
                if (buf_len < buf_offset + 2) return "";
                plen = *(uint16_t*)&buf[buf_offset];
                buf_offset += 2;

            } else if (plen == 127) {
                if (buf_len < buf_offset + 8) return "";
                plen = *(uint64_t*)&buf[buf_offset];
                buf_offset += 8;
            }

            char mask_key[4];
            if (mask) {
                if (buf_len < buf_offset + 4) return "";
                memcpy(mask_key, buf+buf_offset, 4);
                buf_offset += 4;
            }

            if (buf_len < buf_offset + plen) return "";
            std::string res((char*)buf+buf_offset, plen);
            buf_offset += plen;

            if (mask) Unmask(res, mask_key);

            return res;

        } else if (op == 0x8) {
            return ""; /* FIXME: Close frame */

        } else {
            return ""; /* TODO */
        }
    }
};

class WebSocketSession {
public:
    enum State {
        CONNECTING = 0,
        OPEN = 1
    };

    State state;

    WebSocketSession() {
        reset();
    }

    void reset() {
        this->state = CONNECTING;
    }

    static std::string GetServerKey(const std::string &cli_key) {
        static const char *UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        std::string tmp = cli_key + UUID;
        unsigned char hash[SHA1_LEN+1];
        sha1::calc(tmp.data(), tmp.length(), hash);
        hash[SHA1_LEN] = '\0';

        return BinToBase64((char*)hash, NULL, '=');
    }

    void Handshake(StreamSocket *sock, const std::string &buf) {
        std::string cli_key;

        std::string line;
        std::stringstream buf_st(buf);
        while (std::getline(buf_st, line)) {
            line.erase(line.find_last_not_of(" \n\r\t")+1);
            std::size_t pos = line.find(": ");
            if (pos == std::string::npos) continue;

            std::string key = line.substr(0, pos);
            std::string val = line.substr(pos+2);

            std::transform(key.begin(), key.end(), key.begin(), ::tolower);

            if (key == "sec-websocket-key") {
                cli_key = val;
                break;
            }
        }

        if (cli_key.empty()) {
            log("WebSocketSession::Handshake(): Client key was not provided");
            return;
        }

        std::string serv_key = GetServerKey(cli_key);

        std::string resp =
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + serv_key + "\r\n\r\n";

        int buf_written = SE_Send(sock, resp.data(), resp.length(), 0);
        if (buf_written != (int)resp.length()) {
            /* FIXME */
            log("WebSocketSession::Handshake(): Could not send the entire response");
            return;
        }

        state = OPEN;
    }

    int OnWrite(StreamSocket *sock, std::string &sock_buf) {
        if (this->state == WebSocketSession::CONNECTING) return 0;

        std::string buf = WebSocketFrame::Pack(sock_buf);
        int buf_written = SE_Send(sock, buf.data(), buf.length(), 0);

        if (buf_written != (int)buf.length()) {
            if (buf_written >= 0) {
                log("WebSocketSession::OnWrite(): Buffer is not written entirely");
                return -1; /* FIXME: -1 instead of 0, as currently no way to send the frame partially */
            } else {
                log("WebSocketSession::OnWrite(): Socket error while sending the data");
                return -1;
            }
        }

        return 1;
    }

    int OnRead(StreamSocket *sock, std::string &sock_buf) {
        char *buf = ServerInstance->GetReadBuffer();
        const int buf_size = ServerInstance->Config->NetBufferSize;
        int buf_read = SE_Recv(sock, buf, buf_size, 0);

        if (buf_read == 0) {
            return -1;
        } else if (buf_read < 0) {
            log("WebSocketSession::OnRead(): Socket error while receiving the data");
            return -1;
        }

        sock_buf.assign(buf, buf_read);

        if (this->state == WebSocketSession::CONNECTING) {
            this->Handshake(sock, sock_buf);
            return 0;
        } else {
            sock_buf.assign(WebSocketFrame::Unpack(sock_buf));
            return 1;
        }
    }

    void OnClose(StreamSocket *sock) {
    }
};

#ifdef USE_IO_HOOK_PROVIDER

class WebSocketIOHook : public IOHook {
    WebSocketSession sess;

public:
    WebSocketIOHook(IOHookProvider *provider, StreamSocket *sock)
        : IOHook(provider) {

        sock->AddIOHook(this);
    }

    virtual ~WebSocketIOHook() {
    }

    int OnStreamSocketWrite(StreamSocket *sock, std::string &sock_buf) {
        return sess.OnWrite(sock, sock_buf);
    }

    int OnStreamSocketRead(StreamSocket *sock, std::string &sock_buf) {
        return sess.OnRead(sock, sock_buf);
    }

    void OnStreamSocketClose(StreamSocket *sock) {
        sess.OnClose(sock);
    }
};

class WebSocketIOHookProvider : public IOHookProvider {
public:
    WebSocketIOHookProvider(Module *mod)
        : IOHookProvider(mod, "ssl/websocket") {

        ServerInstance->Modules->AddService(*this);
    }

    virtual ~WebSocketIOHookProvider() {
        ServerInstance->Modules->DelService(*this);
    }

    void OnAccept(StreamSocket *sock, irc::sockets::sockaddrs *cli, irc::sockets::sockaddrs *serv) {
        new WebSocketIOHook(this, sock);
    }

    void OnConnect(StreamSocket *sock) {
    }
};

#endif

class ModuleWebSocket : public Module {
#ifndef USE_IO_HOOK_PROVIDER
    ServiceProvider hook_serv;
    WebSocketSession *sesses;
#endif

public:
    ModuleWebSocket()
#ifndef USE_IO_HOOK_PROVIDER
        : hook_serv(this, "m_websocket", SERVICE_IOHOOK)
#endif
    {
#ifndef USE_IO_HOOK_PROVIDER
        sesses = new WebSocketSession[SE_GetMaxFds()];
        ServerInstance->Modules->Attach(I_OnHookIO, this);
#endif
    }

    virtual ~ModuleWebSocket() {
#ifndef USE_IO_HOOK_PROVIDER
        delete [] sesses;
        ServerInstance->Modules->DelService(hook_serv);
#endif
    }

    Version GetVersion() {
        return Version("Allow WebSocket-compliant clients to connect");
    }

    void init() {
#ifdef USE_IO_HOOK_PROVIDER
        new WebSocketIOHookProvider(this);
#else
        ServerInstance->Modules->AddService(hook_serv);
#endif
    }

#ifndef USE_IO_HOOK_PROVIDER
    void OnHookIO(StreamSocket *sock, ListenSocket *serv_sock) {
        if (serv_sock->bind_tag->getString("ssl") != "websocket") return;

        if (sock->GetIOHook()) {
            log("ModuleWebSocket::OnHookIO(): The socket already has a IO hook.");
            return;
        }

        sock->AddIOHook(this);
    }
#endif

    void OnModuleRehash(User *user, const std::string &param) {
        /* FIXME */
    }

#ifndef USE_IO_HOOK_PROVIDER
    void OnStreamSocketAccept(StreamSocket *sock, irc::sockets::sockaddrs *cli, irc::sockets::sockaddrs *serv) {
        sesses[sock->GetFd()].reset();
    }

    int OnStreamSocketWrite(StreamSocket *sock, std::string &sock_buf) {
        return sesses[sock->GetFd()].OnWrite(sock, sock_buf);
    }

    int OnStreamSocketRead(StreamSocket *sock, std::string &sock_buf) {
        return sesses[sock->GetFd()].OnRead(sock, sock_buf);
    }
#endif
};

MODULE_INIT(ModuleWebSocket)
