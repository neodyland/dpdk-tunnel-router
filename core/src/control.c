#include "control.h"

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CTRL_MAX_CLIENTS 8
#define CTRL_IN_MAX 4096
#define CTRL_OUT_MAX (256 * 1024)

struct ctrl_client {
    int fd;
    char in[CTRL_IN_MAX];
    size_t in_len;
    char *out;
    size_t out_len;
    size_t out_off;
};

struct tr_control {
    int listen_fd;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    const struct tr_control_ops *ops;
    void *arg;
    struct ctrl_client clients[CTRL_MAX_CLIENTS];
    int nclients;
};

static void client_close(struct ctrl_client *c)
{
    if (c->fd >= 0)
        close(c->fd);
    free(c->out);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static void client_queue(struct ctrl_client *c, const char *data, size_t len)
{
    if (c->out_off > 0) {
        memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
        c->out_len -= c->out_off;
        c->out_off = 0;
    }
    if (c->out_len + len > CTRL_OUT_MAX)
        return;
    char *p = realloc(c->out, c->out_len + len);
    if (!p)
        return;
    c->out = p;
    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
}

static void respond(struct ctrl_client *c, int ok, const char *text)
{
    char header[64];
    size_t len = text ? strlen(text) : 0;
    int n = snprintf(header, sizeof(header), "%s %zu\n", ok ? "OK" : "ERR",
                     len);
    if (n < 0)
        return;
    client_queue(c, header, (size_t)n);
    if (len)
        client_queue(c, text, len);
}

static void execute_line(struct tr_control *ctrl, struct ctrl_client *c,
                         char *line)
{
    char *body = NULL, *errtext = NULL;
    char *trimmed = tr_trim(line);

    if (!*trimmed)
        return;
    if (strlen(trimmed) >= CTRL_IN_MAX) {
        respond(c, 0, "command too long\n");
        return;
    }
    if (ctrl->ops->execute(ctrl->arg, trimmed, &body, &errtext) == 0) {
        respond(c, 1, body ? body : "");
    } else {
        respond(c, 0, errtext ? errtext : "command failed\n");
    }
    free(body);
    free(errtext);
}

static void client_read(struct tr_control *ctrl, struct ctrl_client *c)
{
    char buf[2048];
    ssize_t n = read(c->fd, buf, sizeof(buf));

    if (n <= 0) {
        client_close(c);
        return;
    }
    if (c->in_len + (size_t)n >= sizeof(c->in)) {
        respond(c, 0, "command line too long\n");
        c->in_len = 0;
        return;
    }
    memcpy(c->in + c->in_len, buf, (size_t)n);
    c->in_len += (size_t)n;
    for (;;) {
        char *nl = memchr(c->in, '\n', c->in_len);
        if (!nl)
            break;
        *nl = '\0';
        execute_line(ctrl, c, c->in);
        size_t used = (size_t)(nl - c->in) + 1;
        memmove(c->in, c->in + used, c->in_len - used);
        c->in_len -= used;
    }
}

static void client_write(struct ctrl_client *c)
{
    if (c->out_off >= c->out_len) {
        c->out_len = 0;
        c->out_off = 0;
        return;
    }
    ssize_t n = write(c->fd, c->out + c->out_off, c->out_len - c->out_off);
    if (n > 0) {
        c->out_off += (size_t)n;
        if (c->out_off == c->out_len) {
            c->out_off = 0;
            c->out_len = 0;
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        client_close(c);
    }
}

struct tr_control *tr_control_create(const char *path,
                                     const struct tr_control_ops *ops,
                                     void *arg, char *err, size_t errlen)
{
    struct tr_control *c;
    struct sockaddr_un addr;
    int fd;
    int flags;

    if (!path || strlen(path) >= sizeof(addr.sun_path)) {
        snprintf(err, errlen, "control socket path too long");
        return NULL;
    }
    c = calloc(1, sizeof(*c));
    if (!c) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    c->ops = ops;
    c->arg = arg;
    c->listen_fd = -1;
    snprintf(c->path, sizeof(c->path), "%s", path);
    for (int i = 0; i < CTRL_MAX_CLIENTS; i++)
        c->clients[i].fd = -1;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket: %s", strerror(errno));
        free(c);
        return NULL;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        snprintf(err, errlen, "bind %s: %s", path, strerror(errno));
        close(fd);
        free(c);
        return NULL;
    }
    chmod(path, 0660);
    if (listen(fd, 16) < 0) {
        snprintf(err, errlen, "listen: %s", strerror(errno));
        close(fd);
        unlink(path);
        free(c);
        return NULL;
    }
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    c->listen_fd = fd;
    return c;
}

void tr_control_poll(struct tr_control *c, int timeout_ms)
{
    struct pollfd pfds[1 + CTRL_MAX_CLIENTS];
    int idx[1 + CTRL_MAX_CLIENTS];
    int n = 0;

    pfds[n].fd = c->listen_fd;
    pfds[n].events = POLLIN;
    idx[n] = -1;
    n++;
    for (int i = 0; i < CTRL_MAX_CLIENTS; i++) {
        if (c->clients[i].fd < 0)
            continue;
        pfds[n].fd = c->clients[i].fd;
        pfds[n].events = POLLIN;
        if (c->clients[i].out_len > c->clients[i].out_off)
            pfds[n].events |= POLLOUT;
        idx[n] = i;
        n++;
    }
    int rc = poll(pfds, (nfds_t)n, timeout_ms);
    if (rc <= 0)
        return;
    if (pfds[0].revents & POLLIN) {
        for (;;) {
            int cfd = accept4(c->listen_fd, NULL, NULL,
                              SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0)
                break;
            int slot = -1;
            for (int i = 0; i < CTRL_MAX_CLIENTS; i++) {
                if (c->clients[i].fd < 0) {
                    slot = i;
                    break;
                }
            }
            if (slot < 0) {
                const char *busy = "ERR 23\nserver busy\n";
                ssize_t ignored = write(cfd, busy, strlen(busy));
                (void)ignored;
                close(cfd);
                continue;
            }
            memset(&c->clients[slot], 0, sizeof(c->clients[slot]));
            c->clients[slot].fd = cfd;
        }
    }
    for (int i = 1; i < n; i++) {
        if (idx[i] < 0)
            continue;
        struct ctrl_client *cl = &c->clients[idx[i]];
        if (cl->fd < 0)
            continue;
        if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            client_close(cl);
            continue;
        }
        if (pfds[i].revents & POLLIN)
            client_read(c, cl);
        if (cl->fd >= 0 && (pfds[i].revents & POLLOUT))
            client_write(cl);
    }
}

void tr_control_destroy(struct tr_control *c)
{
    if (!c)
        return;
    for (int i = 0; i < CTRL_MAX_CLIENTS; i++)
        client_close(&c->clients[i]);
    if (c->listen_fd >= 0)
        close(c->listen_fd);
    if (c->path[0])
        unlink(c->path);
    free(c);
}
