#include "simple_socket.hpp"
#include "simple_socket_wrapper.hpp"

#include <iostream>

namespace simplesocket {

class TcpServer {
public:
    kani::simple_socket::TcpServer server;
};

class TcpClient {
public:
    kani::simple_socket::TcpClient client;
};

class TcpNetClient {
public:
    kani::simple_socket::TcpNetClient net_client;
};

int run_server() {
    // using namespace kani::simple_socket;
    namespace kss = kani::simple_socket;

    const std::string DEFAULT_IP = "localhost";
    const std::string DEFAULT_PORT = "1234";
    const int DEFAULT_PROTOCOL_FAMILY = 0;
    const long DEFAULT_BACKLOG = 0x7fffffff;
    const int DEFAULT_RECV_MSG_LEN = 255;

    kss::TcpServerSocketInfo info;
    info.m_node                 = DEFAULT_IP;
    info.m_service             = DEFAULT_PORT;
    info.m_protocolFamily = DEFAULT_PROTOCOL_FAMILY;
    info.m_backlog            = DEFAULT_BACKLOG;

    kss::TcpServer server(info);

    if (!server.is_valid()) {
        std::cerr << "can't initialized server!" << std::endl;
        return 1;
    }

    if (server.start() != kss::SS_START_RESULT_SUCCESS) {
        std::cerr << "can't start the server!" << std::endl;
        return 1;
    }

    kss::TcpNetClient client;
    std::cout << "waiting for client..." << std::endl;

    while (!server.wait_client(&client)) { }

    std::cout << "client ( " << client.get_host() << " : " << client.get_service() << " ) connected!" << std::endl;

    kss::SendMsg msg;
    msg.m_msg = "Hello, client! I'm a server. Welcome to my simple server 8)";

    if (!server.send_msg(&client, &msg)) {
        std::cerr << "can't sent message to client!" << std::endl;
        return 1;
    }

    std::cout << "sent message to client: " << msg.m_sentLen << "byte" << std::endl;

    kss::RecvMsg response(DEFAULT_RECV_MSG_LEN);

    if (!server.recv_msg(&client, &response)) {
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