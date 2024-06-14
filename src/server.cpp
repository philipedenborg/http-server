#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

struct Headers
{
  Headers() = default;
  Headers(std::string msg_str)
  {
    std::string crlf{"\r\n"};

    auto start_pos = msg_str.find("Host:", 0);
    auto end_pos = msg_str.find(crlf, start_pos);
    host = msg_str.substr(start_pos, end_pos-start_pos);

    // start_pos = msg_str.find("User-Agent:", 0);
    // end_pos = msg_str.find(crlf, start_pos);
    // user_agent = msg_str.substr(start_pos, end_pos-start_pos);
    
    // start_pos = msg_str.find("Accept:", 0);
    // end_pos = msg_str.find(crlf, start_pos);
    // accept = msg_str.substr(start_pos, end_pos-start_pos);
  }
  std::string host;
  std::string user_agent;
  std::string accept;
};

struct Http_request
{
  Http_request(char msg[])
  {
    std::string msg_str{msg};
    std::string crlf{"\r\n"};

    size_t start_pos = 0;
    auto end_pos = msg_str.find(" ", start_pos);
    method = msg_str.substr(start_pos, end_pos-start_pos);

    start_pos = end_pos + 1; 
    end_pos = msg_str.find(" ", start_pos);
    target = msg_str.substr(start_pos, end_pos-start_pos);

    start_pos = end_pos + 1; 
    end_pos = msg_str.find(crlf, start_pos);
    version = msg_str.substr(start_pos, end_pos-start_pos);

    start_pos = end_pos + 1; 
    auto headers_str = msg_str.substr(start_pos, std::string::npos);
    headers = Headers{headers_str};
  } 
  std::string method;
  std::string target;
  std::string version;
  Headers headers;
  std::string body;
};


int main(int argc, char **argv) {
  // Flush after every std::cout / std::cerr
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;
  
  // You can use print statements as follows for debugging, they'll be visible when running tests.
  std::cout << "Logs from your program will appear here!\n";

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return 1;
  }
  
  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }
  
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  int clientSocket = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);

  for (int i = 0; i < 2; ++i)
  {
    char buffer[1024] = {0};
    recv(clientSocket, buffer, sizeof(buffer), 0);
    Http_request http_request{buffer};
    std::cout << "Message from client: " << buffer << std::endl;
    std::cout << "Method: " << http_request.method <<"!EST"<< std::endl;
    std::cout << "Target: " << http_request.target <<"!EST"<< std::endl;
    std::cout << "Version: " << http_request.version <<"!EST"<< std::endl;
    std::cout << "Headers.host: " << http_request.headers.host <<"!EST"<< std::endl;



    std::string crlf = "\r\n"; 
    std::string http_version = "HTTP/1.1 "; 
    std::string headers = ""; 
    std::string body = ""; 

    std::string valid_target = "/";
    std::string status_code = "200 "; 
    std::string reason_phrase = "OK"; 
    if (http_request.target != valid_target)
    {
      status_code = "404 ";
      reason_phrase = "Not Found";
    }

    std::string message = http_version + status_code + reason_phrase + crlf + headers + crlf + body;

    send(clientSocket, message.c_str(), message.length(), 0);
  }  

  close(server_fd);

  return 0;
}
