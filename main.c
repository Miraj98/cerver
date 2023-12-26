#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <ctype.h>

#define PORT 8080
#define MAX_HANDLERS 50
#define MAX_REQ_BUF_SIZE 2048
#define BASE_HEADER_KEYS { "host", "content-type", "content-length", "authorization" }
#define BASE_HEADER_KEYS_LEN sizeof(BASE_HEADER_KEYS) / sizeof(char *)

char *tokenizer(char **base, const char *delim) {
    size_t len = strlen(*base);
    size_t to_check = strlen(delim);

    for (int i = 0; i <= len - to_check; i++) {
        if (strncmp((*base) + i, delim, to_check) == 0) {
            char *ret = *base;
            (*base)[i] = '\0';
            *base = (*base) + i + to_check;
            return ret;
        }
    }
    char *ret = *base;
    *base = NULL;
    return ret;
}

void trim(char **str) {
    while (isspace(**str)) *str += 1;
    char *end_ptr = *str + strlen(*str) - 1;
    while (isspace(*end_ptr)) end_ptr -= 1;
    *(end_ptr + 1) = '\0';
}

typedef enum {
    GET = 1,
    POST
} HTTP_Method;

typedef struct {
    char *keys[24];
    char *values[24];
    size_t len;
} Headers;

char *header_get(Headers *headers, char *key) {
    for (int i = 0; i < headers->len; i++) {
        if (strcasecmp(headers->keys[i], key) == 0) {
            return headers->values[i];
        }
    }
    return NULL;
}

int header_add(Headers *headers, char *key, char *val) {
    if (headers->len == 24) {
        fprintf(stderr, "Max header buffer size reached. Current max headers possible: 24\n");
        return 0;
    }
    headers->keys[headers->len] = key;
    headers->values[headers->len] = val;
    headers->len += 1;
    return 1;
}

typedef struct {
    HTTP_Method method;
    Headers headers;
    char *path;
    char *proto;

    int error;
    char *error_msg;
} HTTP_Request;

void print_http_request(HTTP_Request *req) {
    if (req->error) {
        fprintf(stderr, "[ERROR] %s\n", req->error_msg);
        return;
    }
    printf("{\n");
    {
        printf("    method: %s\n", req->method == 1 ? "GET" : "POST");
        printf("    path: %s\n", req->path);
        printf("    proto: %s\n", req->proto);
        printf("    headers: {\n");
        for (int i = 0; i < req->headers.len; i++) {
            printf("        %s: %s\n", req->headers.keys[i], req->headers.values[i]);
        }
        printf("    }\n");
    }
    printf("}\n");
}

HTTP_Request parse_raw_req(char *req) {
    HTTP_Request out = {0};
    char *method = strsep(&req, " ");
    // Parse method
    HTTP_Method m;
    if (strcmp(method, "GET") == 0) {
        m = GET;
    } else if(strcmp(method, "POST") == 0) {
        m = POST;
    } else {
        out.error = 1;
        out.error_msg = malloc(strlen("Unsupported HTTP method: ") + strlen(method) + 1);
        sprintf(out.error_msg, "Unsupported HTTP method: %s", method);
        return out;
    }
    out.method = m;
    // Parse resource path
    out.path = strsep(&req, " ");
    if (out.path == NULL) {
        out.error = 1;
        out.error_msg = "HTTP spec requires a resource path";
        return out;
    }
    // Parse HTTP version
    out.proto = tokenizer(&req, "\r\n");
    if (out.proto == NULL) {
        out.error = 1;
        out.error_msg = "HTTP spec requires 'HTTP/<version>' at the end of first line";
        return out;
    }
    // Parse headers
    char *header;
    while ((header = tokenizer(&req, "\r\n")) != NULL) {
        if (strcmp(header, "") == 0) {
            break;
        }
        char *header_key = tokenizer(&header, ":");
        trim(&header_key);
        trim(&header);
        header_add(&out.headers, header_key, header);
    }
    return out;
}

typedef struct {
    int status;
    char *status_text;
    Headers headers;
    uint8_t *data;
} HTTP_Response;

char *serialize_response(char buf[10240], HTTP_Response *resp) {
    int offset = sprintf(buf, "HTTP/1.1 %d %s\r\n", resp->status, resp->status_text);
    for (int i = 0; i < resp->headers.len; i++) {
        offset += sprintf(buf + offset, "%s: %s\r\n", resp->headers.keys[i], resp->headers.values[i]);
    }
    offset += sprintf(buf + offset, "\r\n");
    if (resp->data) {
        offset += sprintf(buf + offset, "%s",  (char *)resp->data);
        offset += sprintf(buf + offset, "\r\n");
    }
    return buf;
}

typedef struct {
    char *path_str[MAX_HANDLERS];
    HTTP_Method methods[MAX_HANDLERS];
    HTTP_Response (*handlers[MAX_HANDLERS])(HTTP_Request *);
    size_t len;
} Router;

void add_handler(Router *router, HTTP_Method m, const char *path, HTTP_Response (*handler)(HTTP_Request *)) {
    if (router->len >= MAX_HANDLERS) {
        perror("Cannot add request handler\n");
        return;
    }
    char *new_path_str = malloc(sizeof(char) * (strlen(path) + 1));
    if (new_path_str == NULL) {
        perror("Cannot add request handler because cannot allocate memory for path str\n");
        return;
    }
    strcpy(new_path_str, path);
    router->path_str[router->len] = new_path_str;
    router->methods[router->len] = m;
    router->handlers[router->len] = handler;
    router->len += 1;
}

HTTP_Response exec_req_handler(Router *r, HTTP_Request *req) {
    for (int i = 0; i < r->len; i++) {
        if (r->methods[i] == req->method && strcmp(r->path_str[i], req->path) == 0) {
            return (*r->handlers[i])(req);
        }
    }
    HTTP_Response resp = { .status = 404 };
    return resp;
}

Router *create_router() {
    Router *ret = calloc(1, sizeof(Router));
    return ret;
}

void free_router(Router *r) {
    for (int i = 0; i < r->len; i++) {
        free(r->path_str[i]);
    }
    free(r);
}

HTTP_Response ok_resp(HTTP_Request *req) {
    HTTP_Response resp = {0};
    resp.status = 200;
    resp.status_text = "OK";
    header_add(&resp.headers, "Content-Type", "application/json");
    char *data =  "{\"hello\": \"world\"}\r\n";
    resp.data = malloc(sizeof(char) * strlen(data));
    memcpy(resp.data, data, strlen(data));
    return resp;
}


int main(void) {
    Router *router = create_router();
    add_handler(router, GET, "/", ok_resp);

    if (router == NULL) {
        fprintf(stderr, "Unable to create router\n");
        exit(0);
    }
    int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1)  {
        fprintf(stderr, "Unable to open a socket\n");
        exit(0);
    }
    struct sockaddr_in server_addr_info = {0};
    int addrlen = sizeof(server_addr_info);
    server_addr_info.sin_family = AF_INET;
    server_addr_info.sin_addr.s_addr = INADDR_ANY;
    server_addr_info.sin_port = htons(PORT);
    if (bind(sock_fd, (struct sockaddr *)&server_addr_info, addrlen) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(sock_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    printf("Server is listening on port %d\n", PORT);

    struct sockaddr_in client_addr_info = {0};
    size_t client_addr_len = sizeof(client_addr_info);
    int incoming = accept(sock_fd, (struct sockaddr *)&client_addr_info, (socklen_t*)&client_addr_len);
    /*
    char *msg = "Hello, world\n";
    send(incoming, msg, strlen(msg),0);
    */

    char buffer[MAX_REQ_BUF_SIZE];
    while (1) {
        memset(buffer, 0, MAX_REQ_BUF_SIZE);
        int bytes_read = read(incoming, buffer, MAX_REQ_BUF_SIZE - 1);
        if (bytes_read <= 0) break;
        if (strcmp(buffer, "quit\n") == 0) break;
        HTTP_Request req = parse_raw_req(buffer);
        print_http_request(&req);
        HTTP_Response http_response = exec_req_handler(router, &req);
        char buf[10240] = {0};
        char *final = serialize_response(buf, &http_response);
        // char *resp = "HTTP/1.1 200 OK\r\n\r\nHello world\r\n";
        send(incoming, final, strlen(final), 0);
        close(incoming);
    }

    close(sock_fd);
    return 0;
}
