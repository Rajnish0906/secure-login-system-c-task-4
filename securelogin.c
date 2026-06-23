#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

#define PORT 8080
#define BUFFER_SIZE 8192

typedef struct {
    char username[50];
    char password_hash[100]; 
} User;

User mock_db[10];
int user_count = 0;
char active_session_user[50] = "";

void mock_hash(const char *password, char *output) {
    unsigned long hash = 5381;
    int c;
    while ((c = (unsigned char)*password++)) {
        hash = ((hash << 5) + hash) + c;
    }
    sprintf(output, "bcrypt_mock_hash_%lu", hash);
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit((unsigned char)a) && isxdigit((unsigned char)b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

void get_param(const char *body, const char *param, char *value) {
    const char *p = strstr(body, param);
    if (p) {
        p += strlen(param);
        int i = 0;
        while (*p && *p != '&' && *p != '\r' && *p != '\n') {
            value[i++] = *p++;
        }
        value[i] = '\0';
        char decoded[256];
        url_decode(decoded, value);
        strcpy(value, decoded);
    } else {
        value[0] = '\0';
    }
}

void build_html(char *response_body, const char *content) {
    sprintf(response_body,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<!DOCTYPE html><html><head><title>Secure Login System</title>"
        "<style>"
        "body { font-family: Arial; background: #f4f4f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }"
        ".card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); width: 300px; text-align: center; }"
        "input { width: 90%%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }"
        "button { width: 97%%; padding: 10px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }"
        "button.logout { background: #dc3545; }"
        ".error { color: red; font-size: 14px; }"
        "a { color: #007bff; text-decoration: none; }"
        "</style></head><body><div class='card'>%s</div></body></html>", content);
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    recv(client_socket, buffer, BUFFER_SIZE - 1, 0);

    char response[BUFFER_SIZE] = {0};

    if (strncmp(buffer, "GET /logout", 11) == 0) {
        active_session_user[0] = '\0'; 
        build_html(response, "<h2>Logged Out Successfully</h2><br><a href='/login'>Go to Login</a>");
    }
    else if (strncmp(buffer, "GET /dashboard", 14) == 0) {
        if (strlen(active_session_user) == 0) {
            build_html(response, "<h2>Access Denied</h2><p class='error'>Please login first.</p><br><a href='/login'>Login</a>");
        } else {
            char welcome[500];
            sprintf(welcome, "<h2>Welcome, %s! 👋</h2><p style='color:green;'>Secure Session Active.</p><br><form action='/logout' method='GET'><button class='logout' type='submit'>Logout</button></form>", active_session_user);
            build_html(response, welcome);
        }
    }
    else if (strncmp(buffer, "POST /login", 11) == 0) {
        char *body = strstr(buffer, "\r\n\r\n");
        char user[50] = {0}, pass[50] = {0}, input_hash[100] = {0};
        if (body) {
            body += 4;
            get_param(body, "username=", user);
            get_param(body, "password=", pass);
        }

        mock_hash(pass, input_hash);
        int authenticated = 0;
        
        for (int i = 0; i < user_count; i++) {
            if (strcmp(mock_db[i].username, user) == 0 && strcmp(mock_db[i].password_hash, input_hash) == 0) {
                authenticated = 1;
                strcpy(active_session_user, user);
                break;
            }
        }

        if (authenticated) {
            build_html(response, "<h2>Login Successful!</h2><br><a href='/dashboard'>Go to Dashboard</a>");
        } else {
            build_html(response, "<h2>Secure Login</h2><p class='error'>Invalid credentials!</p><br><a href='/login'>Try Again</a>");
        }
    }
    else if (strncmp(buffer, "POST /register", 14) == 0) {
        char *body = strstr(buffer, "\r\n\r\n");
        char user[50] = {0}, pass[50] = {0};
        if (body) {
            body += 4;
            get_param(body, "username=", user);
            get_param(body, "password=", pass);
        }

        if (strlen(user) == 0 || strlen(pass) == 0) {
            build_html(response, "<h2>Error</h2><p class='error'>Fields cannot be empty.</p><br><a href='/register'>Try Again</a>");
        } else if (user_count >= 10) {
            build_html(response, "<h2>Error</h2><p class='error'>DB Full.</p><br><a href='/login'>Login</a>");
        } else {
            strcpy(mock_db[user_count].username, user);
            mock_hash(pass, mock_db[user_count].password_hash);
            user_count++;
            build_html(response, "<h2>Registration Successful!</h2><br><a href='/login'>Login Now</a>");
        }
    }
    else if (strncmp(buffer, "GET /register", 13) == 0) {
        build_html(response, "<h2>User Registration</h2><form method='POST' action='/register'><input type='text' name='username' placeholder='Username' required><input type='password' name='password' placeholder='Password' required><button type='submit'>Register</button></form><br><a href='/login'>Login instead</a>");
    }
    else { 
        build_html(response, "<h2>Secure Login</h2><form method='POST' action='/login'><input type='text' name='username' placeholder='Username' required><input type='password' name='password' placeholder='Password' required><button type='submit'>Login</button></form><br><a href='/register'>Create an account</a>");
    }

    send(client_socket, response, (int)strlen(response), 0);
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    printf("=============================================\n");
    printf("      🌐 SECURE WEB LOGIN SERVER (C) 🌐       \n");
    printf("=============================================\n");
    printf("[+] Server started on http://127.0.0.1:8080\n");
    printf("[+] Press Ctrl+C to terminate server.\n");

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket >= 0) {
            handle_client(client_socket);
        }
    }

    return 0;
}