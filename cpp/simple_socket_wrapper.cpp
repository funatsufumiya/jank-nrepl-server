#include "simple_socket.hpp"
#include "simple_socket_wrapper.hpp"

#include <iostream>
#include <string>

namespace simplesocket {

namespace kss = kani::simple_socket;

class RecvMsgImpl : public RecvMsg {
public:
    kss::RecvMsg msg;

    RecvMsgImpl(int length): msg(kss::RecvMsg(length)) {
    }

    int recvLen(){
        return msg.m_recvLen;
    }

    std::string_view get_msg(){
        return msg.m_msg;
    }

    std::string get_msg_str(){
        return std::string(msg.m_msg);
    }

    void* get_msg_impl(){
        return &msg;
    }
};

class SendMsgImpl : public SendMsg {
public:
    kss::SendMsg msg;

    SendMsgImpl(){}
    SendMsgImpl(std::string s){
        msg.m_msg = s;
    }

    int sentLen(){
        return msg.m_sentLen;
    }

    std::string_view get_msg(){
        return msg.m_msg;
    }

    std::string get_msg_str(){
        return std::string(msg.m_msg);
    }

    void* get_msg_impl(){
        return &msg;
    }
};

// class TcpClientImpl : public TcpClient {
// public:
//     kani::simple_socket::TcpClient client;
// };

class TcpNetClientImpl : public TcpNetClient {
public:
    kani::simple_socket::TcpNetClient client;

    // std::string_view get_host(){
    //     return client.get_host();
    // }

    // std::string_view get_service(){
    //     return client.get_service();
    // }

    std::string get_host(){
        return std::string(client.get_host());
    }

    std::string get_service(){
        return std::string(client.get_service());
    }

    void close(){
        client.close();
    }

    // kani::simple_socket::TcpNetClient& get_client(){
    //     return client;
    // }

    void* get_client_impl(){
        return &client;
    }
};

class TcpServerImpl : public TcpServer {
public:
    kani::simple_socket::TcpServer server;

    TcpServerImpl(kss::TcpServerSocketInfo& info) : server(info) {}

    bool is_valid(){
        return server.is_valid();
    }

    bool start(){
        return server.start() == kss::SS_START_RESULT_SUCCESS;
    }

    bool wait_client(TcpNetClient* client){
        return server.wait_client(ptr_from(client));
    }

    bool send_msg(TcpNetClient* client, SendMsg* msg){
        return server.send_msg(ptr_from(client), msg_from(msg));
    }

    bool recv_msg(TcpNetClient* client, RecvMsg* msg){
        return server.recv_msg(ptr_from(client), msg_from(msg));
    }

    void stop(){
        server.stop();
    }

private:
    kani::simple_socket::TcpNetClient* ptr_from(TcpNetClient* client){
        return (kani::simple_socket::TcpNetClient*)(client->get_client_impl());
    }

    kani::simple_socket::SendMsg* msg_from(SendMsg* client){
        return (kani::simple_socket::SendMsg*)(client->get_msg_impl());
    }

    kani::simple_socket::RecvMsg* msg_from(RecvMsg* client){
        return (kani::simple_socket::RecvMsg*)(client->get_msg_impl());
    }
};

std::shared_ptr<TcpServer> create_tcp_server(std::string host, int port){
    // namespace kss = kani::simple_socket;

    std::string port_s = std::to_string(port);

    kss::TcpServerSocketInfo info;
    info.m_node = host;
    info.m_service = port_s;
    info.m_protocolFamily = 0;
    info.m_backlog = 0x7fffffff;

    // kss::TcpServer server(info);
    return std::make_shared<TcpServerImpl>(info);
}

std::shared_ptr<SendMsg> create_send_msg(){
    return std::make_shared<SendMsgImpl>();
}

std::shared_ptr<SendMsg> create_send_msg(std::string s){
    return std::make_shared<SendMsgImpl>(s);
}

std::shared_ptr<RecvMsg> create_recv_msg(int len){
    return std::make_shared<RecvMsgImpl>(len);
}

std::shared_ptr<TcpNetClient> create_tcp_net_client(){
    return std::make_shared<TcpNetClientImpl>();
}

int run_server() {
    // using namespace kani::simple_socket;

    // namespace kss = kani::simple_socket;

    // const std::string DEFAULT_IP = "localhost";
    // const std::string DEFAULT_PORT = "1234";
    // const int DEFAULT_PROTOCOL_FAMILY = 0;
    // const long DEFAULT_BACKLOG = 0x7fffffff;
    // const int DEFAULT_RECV_MSG_LEN = 255;

    // kss::TcpServerSocketInfo info;
    // info.m_node                 = DEFAULT_IP;
    // info.m_service             = DEFAULT_PORT;
    // info.m_protocolFamily = DEFAULT_PROTOCOL_FAMILY;
    // info.m_backlog            = DEFAULT_BACKLOG;

    // kss::TcpServer server(info);

    auto server = create_tcp_server("localhost", 1234);

    if (!server->is_valid()) {
        std::cerr << "can't initialized server!" << std::endl;
        return 1;
    }

    if (!server->start()) {
        std::cerr << "can't start the server!" << std::endl;
        return 1;
    }

    // kss::TcpNetClient client;
    auto client = create_tcp_net_client();
    std::cout << "waiting for client..." << std::endl;

    while (!server->wait_client(client.get())) { }

    std::cout << "client ( " << client->get_host() << " : " << client->get_service() << " ) connected!" << std::endl;

    auto msg = create_send_msg("Hello, client! I'm a server. Welcome to my simple server 8)");

    if (!server->send_msg(client.get(), msg.get())) {
        std::cerr << "can't sent message to client!" << std::endl;
        return 1;
    }

    std::cout << "sent message to client: " << msg->sentLen() << "byte" << std::endl;

    auto response = create_recv_msg(255);

    if (!server->recv_msg(client.get(), response.get())) {
        std::cerr << "can't received message from client!" << std::endl;
        return 1;
    }

    std::cout << "received message from client: " << response->recvLen() << "byte" << std::endl;
    std::cout << "Client: " << response->get_msg() << std::endl;

    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;
    client->close();

    std::cout << "stopping the server..." << std::endl;
    server->stop();

    std::cout << "server stopped" << std::endl;
    return 0;
}

} // namespace simplesocket