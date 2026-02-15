#include "simple_socket.hpp"
#include "simple_socket_wrapper.hpp"

#include <iostream>
#include <string>

namespace simplesocket {

namespace kss = kani::simple_socket;

class SendMsg {
public:
    kss::SendMsg msg;

    int sentLen(){
        return msg.m_sentLen;
    }
};

class TcpClient {
public:
    kani::simple_socket::TcpClient client;
};

class TcpNetClient {
public:
    kani::simple_socket::TcpNetClient client;

    std::string_view get_host(){
        return client.get_host();
    }

    std::string_view get_service(){
        return client.get_service();
    }

    void close(){
        client.close();
    }
};

class TcpServer {
public:
    kani::simple_socket::TcpServer server;

    bool is_valid(){
        return server.is_valid();
    }

    bool start(){
        return server.start() == kss::SS_START_RESULT_SUCCESS;
    }

    bool wait_client(TcpNetClient& client){
        return server.wait_client(&client.client);
    }

    bool send_msg(TcpNetClient& client, SendMsg& msg){
        return server.send_msg(&client.client, &msg.msg);
    }

    void stop(){
        server.stop();
    }
};

TcpServer create_tcp_server(std::string host, int port){
    // namespace kss = kani::simple_socket;

    std::string port_s = std::to_string(port);

    kss::TcpServerSocketInfo info;
    info.m_node = host;
    info.m_service = port_s;
    info.m_protocolFamily = 0;
    info.m_backlog = 0x7fffffff;

    kss::TcpServer server(info);
    return TcpServer{ server };
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

    if (!server.is_valid()) {
        std::cerr << "can't initialized server!" << std::endl;
        return 1;
    }

    if (!server.start()) {
        std::cerr << "can't start the server!" << std::endl;
        return 1;
    }

    // kss::TcpNetClient client;
    TcpNetClient client;
    std::cout << "waiting for client..." << std::endl;

    while (!server.wait_client(client)) { }

    std::cout << "client ( " << client.get_host() << " : " << client.get_service() << " ) connected!" << std::endl;

    SendMsg msg;
    msg.msg.m_msg = "Hello, client! I'm a server. Welcome to my simple server 8)";

    if (!server.send_msg(client, msg)) {
        std::cerr << "can't sent message to client!" << std::endl;
        return 1;
    }

    std::cout << "sent message to client: " << msg.sentLen() << "byte" << std::endl;

    kss::RecvMsg response(DEFAULT_RECV_MSG_LEN);

    if (!server.server.recv_msg(&client.client, &response)) {
        std::cerr << "can't received message from client!" << std::endl;
        return 1;
    }

    std::cout << "received message from client: " << response.m_recvLen << "byte" << std::endl;
    std::cout << "Client: " << response.m_msg << std::endl;

    std::cout << "Perfect! Now, say to goodbye :')" << std::endl;
    client.close();

    std::cout << "stopping the server..." << std::endl;
    server.stop();

    std::cout << "server stopped" << std::endl;
    return 0;
}

} // namespace simplesocket