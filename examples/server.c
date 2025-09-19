#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

volatile int running = 1;

void signal_handler(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[1024];
    int opt = 1;
    
    printf("TCP Server starting...\n");
    printf("PID: %d\n", getpid());
    printf("UID: %d, GID: %d\n", getuid(), getgid());
    
    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(1);
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(1);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(1);
    }
    
    printf("Server listening on port 8080...\n");
    printf("Try: telnet localhost 8080\n");
    
    while (running) {
        printf("Waiting for connection...\n");
        
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running) {
                perror("accept failed");
            }
            break;
        }
        
        printf("Client connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));
        
        // Simple echo server
        while (running) {
            ssize_t bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) break;
            
            buffer[bytes] = '\0';
            printf("Received: %s", buffer);
            
            // Echo back with a prefix
            char response[1024];
            snprintf(response, sizeof(response), 
                     "ISOLATED-SERVER: %s", buffer);
            
            send(client_fd, response, strlen(response), 0);
        }
        
        close(client_fd);
        printf("Client disconnected\n");
    }
    
    close(server_fd);
    printf("Server shutdown complete\n");
    return 0;
}
