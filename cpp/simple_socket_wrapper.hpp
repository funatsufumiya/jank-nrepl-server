#include <string>
#include <memory>

namespace simplesocket {

class RecvMsg {
public:
    // RecvMsg(int len){}
    virtual ~RecvMsg(){}
    virtual int recvLen() = 0;
    virtual std::string_view get_msg() = 0;
    virtual void* get_msg_impl() = 0;
};

class SendMsg {
public:
    // virtual SendMsg();
    // virtual SendMsg(std::string s);
    virtual ~SendMsg(){}
    virtual int sentLen() = 0;
    virtual std::string_view get_msg() = 0;
    virtual void* get_msg_impl() = 0;
};

// class TcpClient {
// public:
// };

class TcpNetClient {
public:
    // TcpNetClient(){}
    virtual ~TcpNetClient(){}
    virtual std::string_view get_host() = 0;
    virtual std::string_view get_service() = 0;
    virtual void close() = 0;
    virtual void* get_client_impl() = 0;
};

class TcpServer {
public:
    // TcpServer(){}
    virtual ~TcpServer(){}
    virtual bool is_valid() = 0;
    virtual bool start() = 0;
    virtual bool wait_client(TcpNetClient& client) = 0;
    virtual bool send_msg(TcpNetClient& client, SendMsg& msg) = 0;
    virtual bool recv_msg(TcpNetClient& client, RecvMsg& msg) = 0;
    virtual void stop() = 0;
};

std::shared_ptr<TcpServer> create_tcp_server(std::string host, int port);
std::shared_ptr<SendMsg> create_send_msg();
std::shared_ptr<RecvMsg> create_recv_msg();

int run_server();

} // namespace simplesocket