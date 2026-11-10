/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
/* A single-ID user namespace reports EINVAL for unmapped IDs. fakeroot
 * recognizes EPERM as an unprivileged chown and stores ownership itself. */
#define WRAP(name,args,call) int name args { \
 static int (*next) args; \
 if (!next) next = dlsym(RTLD_NEXT, #name); \
 int result=next call; \
 if(result == -1 && errno == EINVAL && \
    ((u != 0 && u != (uid_t)-1) || (g != 0 && g != (gid_t)-1))) errno=EPERM; \
 return result; \
}
WRAP(chown,(const char *p,uid_t u,gid_t g),(p,u,g))
WRAP(lchown,(const char *p,uid_t u,gid_t g),(p,u,g))
WRAP(fchown,(int fd,uid_t u,gid_t g),(fd,u,g))
WRAP(fchownat,(int fd,const char *p,uid_t u,gid_t g,int flags),(fd,p,u,g,flags))
