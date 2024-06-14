#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

const std::string crlf = "\r\n"; 
 
std::string extract_header(const std::string msg_str, const std::string header_str)
{
  auto start_pos = msg_str.find(header_str, 0) + header_str.length();
  auto end_pos = msg_str.find(crlf, start_pos);
  if (end_pos != std::string::npos)
  {
    return msg_str.substr(start_pos, end_pos-start_pos);
  }

  return "";
}

struct Headers
{
  Headers() = default;
  Headers(std::string msg_str)
  {
    host = extract_header(msg_str, "Host: ");
    user_agent = extract_header(msg_str, "User-Agent: ");
    content_type = extract_header(msg_str, "Content Type: ");
    content_length = extract_header(msg_str, "Content Length: ");
  }
  std::string host;
  std::string user_agent;
  std::string accept;
  std::string content_type;
  std::string content_length;
};

bool is_target_type(const std::string& type_str, const std::string& target)
{
  return target.substr(0, type_str.length()) == type_str;
}

bool is_echo_endpoint(const std::string& target)
{
  const std::string echo_str = "/echo/";
  return is_target_type(echo_str, target);
}

bool is_user_agent_endpoint(const std::string& target)
{
  const std::string user_agent_str = "/user-agent";
  return is_target_type(user_agent_str, target);

}

bool is_files_endpoint(const std::string& target)
{
  const std::string files_str = "/files";
  return is_target_type(files_str, target);
}

enum class Http_method
{
  GET,
  POST,
  NONE
};

Http_method string_to_http_method(const std::string& s)
{
  if (s == "GET")
  {
    return Http_method::GET;
  }
  if (s == "POST")
  {
    return Http_method::POST;
  }  
  else return Http_method::NONE;
}
struct Http_request
{
  Http_request(char msg[])
  {
    std::string msg_str{msg};

    size_t start_pos = 0;
    auto end_pos = msg_str.find(" ", start_pos);
    method = string_to_http_method(msg_str.substr(start_pos, end_pos-start_pos));

    start_pos = end_pos + 1; 
    end_pos = msg_str.find(" ", start_pos);
    target = msg_str.substr(start_pos, end_pos-start_pos);

    start_pos = end_pos + 1; 
    end_pos = msg_str.find(crlf, start_pos);
    version = msg_str.substr(start_pos, end_pos-start_pos);

    start_pos = end_pos + 1; 
    auto headers_str = msg_str.substr(start_pos, std::string::npos);
    headers = Headers{headers_str};

    auto body_delim = crlf + crlf;
    auto body_start_pos = msg_str.find(body_delim, start_pos) + body_delim.length();
    body = msg_str.substr(body_start_pos, std::string::npos);
  } 
  Http_method method;
  std::string target;
  std::string version;
  Headers headers;
  std::string body;
};

bool handle_read_from_file(std::string& body, std::string& headers, const std::string& file_path, const Http_request& http_request)
{  
  FILE* fp = fopen(file_path.c_str(), "r");
  if (fp)
  {
    std::cout << "Found file: " << file_path << std::endl;
    char buf[1000] = "";
    fgets(buf, sizeof(buf), fp);
    body = buf;
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    std::cout << "Size: " << file_size << std::endl;
    headers += "Content-Type: application/octet-stream" + crlf;
    headers += "Content-Length: " + std::to_string(file_size) + crlf;
    fclose(fp);
    return true;
  }
  else
  {
    return false;
  }
}

bool handle_write_to_file(std::string& body, std::string& headers, const std::string& file_path, const Http_request& http_request)
{  
  FILE* fp = fopen(file_path.c_str(), "w");
  if (fp)
  {
    std::cout << "Created file: " << file_path << std::endl;
    fprintf(fp, http_request.body.c_str());
    fclose(fp);
    return true;
  }
  else
  {
    return false;
  }
}


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

  std::string dir_path;
  if (argc > 2)
  {
      std::cout << "argument 1: " << argv[1] << std::endl;
      std::cout << "argument 2: " << argv[2] << std::endl;
      dir_path = argv[2];  
  }

  while (true)  
  {
    int clientSocket = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);


    char buffer[1024] = {0};
    recv(clientSocket, buffer, sizeof(buffer), 0);
    Http_request http_request{buffer};
    std::cout << "Message from client: " << buffer << std::endl;

    std::string http_version = "HTTP/1.1 "; 
    std::string headers = ""; 
    std::string body = ""; 
    std::string status_code = "200 "; 
    std::string reason_phrase = "OK"; 

    if (is_echo_endpoint(http_request.target))
    {
      std::cout << "Echo endpoint" << std::endl;
      std::string echo_str = "/echo/";
      auto start_pos = http_request.target.find(echo_str.c_str(), 0) + echo_str.length();
      body = http_request.target.substr(start_pos, std::string::npos);
      headers += "Content-Type: text/plain" + crlf;
      headers += "Content-Length: " + std::to_string(body.size()) + crlf;
    }
    else if (is_user_agent_endpoint(http_request.target))
    {
      std::cout << "User-Agent endpoint" << std::endl;
      body = http_request.headers.user_agent;
      headers += "Content-Type: text/plain" + crlf;
      headers += "Content-Length: " + std::to_string(body.size()) + crlf;
    }
    else if (is_files_endpoint(http_request.target))
    {
      std::cout << "Files endpoint" << std::endl;
      std::string files_str = "/files/";
      auto start_pos = http_request.target.find(files_str.c_str(), 0) + files_str.length();
      std::string file_name = http_request.target.substr(start_pos, std::string::npos);
      std::string file_path = dir_path + file_name;

      bool isSuccess = false;
      switch(http_request.method)
      {
        case Http_method::GET:
          isSuccess = handle_read_from_file(body, headers, file_path, http_request);
          break;
        case Http_method::POST:
          if (isSuccess = handle_write_to_file(body, headers, file_path, http_request))
          {
            status_code = "201 ";
            reason_phrase = "Created";
          }          
        default:
          break;
      }
      if (!isSuccess)
      {
        std::cout << "No file: " << file_path << std::endl;
        status_code = "404 ";
        reason_phrase = "Not Found";
      }
    }
    else if (http_request.target != "/")
    {
      status_code = "404 ";
      reason_phrase = "Not Found";
    }

    std::string response = http_version + status_code + reason_phrase + crlf + headers + crlf + body;

    std::cout << "Response: " << response << std::endl;
    send(clientSocket, response.c_str(), response.length(), 0);
  }

  close(server_fd);

  return 0;
}
