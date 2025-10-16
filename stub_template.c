#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const unsigned char *key, int keylen) {
    int i, j;
    unsigned char temp;
    
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keylen]) % 256;
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    
    ctx->i = ctx->j = 0;
}

unsigned char rc4_byte(RC4_CTX *ctx) {
    unsigned char temp;
    
    ctx->i = (ctx->i + 1) % 256;
    ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;
    
    temp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = temp;
    
    return ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
}

void rc4_crypt(RC4_CTX *ctx, unsigned char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        data[i] ^= rc4_byte(ctx);
    }
}

void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Embedded encrypted payload - will be replaced by binlocker
unsigned char encrypted_payload[] = {PAYLOAD_DATA};
size_t payload_size = PAYLOAD_SIZE;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        return 128;
    }
    
    char *password = argv[1];
    size_t password_len = strlen(password);
    
    // Decrypt the payload with the password
    RC4_CTX ctx;
    rc4_init(&ctx, (unsigned char*)password, password_len);
    rc4_crypt(&ctx, encrypted_payload, payload_size);
    
    // Verify decryption worked
    if (payload_size >= 4) {
        unsigned int magic = *(unsigned int*)encrypted_payload;
        if (magic != 0x464c457f) {  // ELF magic number
            return 128;
        }
    }
    
    secure_wipe(password, password_len);
    
    // Create anonymous file descriptor using memfd_create syscall
    int memfd = syscall(SYS_memfd_create, "be", MFD_CLOEXEC);
    if (memfd == -1) {
        return 128;
    }
    
    // Write the decrypted binary to the anonymous file
    if (write(memfd, encrypted_payload, payload_size) != (ssize_t)payload_size) {
        close(memfd);
        return 128;
    }
    
    // Seek to beginning
    if (lseek(memfd, 0, SEEK_SET) == -1) {
        close(memfd);
        return 128;
    }
    
    // Prepare arguments for execution
    char **new_argv = malloc(argc * sizeof(char*));
    if (!new_argv) {
        close(memfd);
        return 128;
    }
    
    // Create path to the anonymous file descriptor
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", memfd);
    
    new_argv[0] = proc_path;
    for (int i = 2; i < argc; i++) {
        new_argv[i-1] = argv[i];
    }
    new_argv[argc-1] = NULL;
    
    extern char **environ;
    execve(proc_path, new_argv, environ);
    
    free(new_argv);
    close(memfd);
    return 128;
}
