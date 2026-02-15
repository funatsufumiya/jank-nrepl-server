namespace simplesocket {

class TcpServer;
class TcpClient;
class TcpNetClient;

TcpServer create_tcp_server(std::string host, int port);
bool is_valid(TcpServer& server);
bool start(TcpServer& server);

int run_server();

} // namespace simplesocket