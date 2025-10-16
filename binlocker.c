#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

// RC4 implementation
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

// Secure memory wiping
void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Read entire file into memory
unsigned char* read_file(const char* filename, size_t* size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char* data = malloc(*size);
    if (!data) {
        fclose(file);
        return NULL;
    }
    
    if (fread(data, 1, *size, file) != *size) {
        free(data);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    return data;
}

// Convert binary data to C array format
void data_to_c_array(const unsigned char* data, size_t size, FILE* out) {
    fprintf(out, "{");
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) {
            fprintf(out, "\n    ");
        }
        fprintf(out, "0x%02x", data[i]);
        if (i < size - 1) {
            fprintf(out, ", ");
        }
    }
    fprintf(out, "\n}");
}

// Read template file and replace placeholders
int process_template(const char* template_path, const unsigned char* payload_data, size_t payload_size, const char* output_path) {
    FILE* template_file = fopen(template_path, "r");
    if (!template_file) {
        perror("Failed to open template file");
        return -1;
    }
    
    FILE* output_file = fopen(output_path, "w");
    if (!output_file) {
        perror("Failed to create output file");
        fclose(template_file);
        return -1;
    }
    
    char line[4096];
    while (fgets(line, sizeof(line), template_file)) {
        if (strstr(line, "PAYLOAD_DATA")) {
            // Replace PAYLOAD_DATA with actual data, keeping the variable declaration
            char *start = strstr(line, "{");
            if (start) {
                // Write everything before the opening brace
                *start = '\0';
                fputs(line, output_file);
                // Write the data array
                data_to_c_array(payload_data, payload_size, output_file);
                // Write the closing brace and semicolon
                fprintf(output_file, ";\n");
            } else {
                // Fallback: just replace the placeholder
                data_to_c_array(payload_data, payload_size, output_file);
            }
        } else if (strstr(line, "PAYLOAD_SIZE")) {
            // Replace PAYLOAD_SIZE with actual size, keeping the variable declaration
            char *start = strstr(line, "PAYLOAD_SIZE");
            if (start) {
                // Write everything before PAYLOAD_SIZE
                *start = '\0';
                fputs(line, output_file);
                // Write the actual size
                fprintf(output_file, "%zu", payload_size);
                // Write everything after PAYLOAD_SIZE
                fputs(start + strlen("PAYLOAD_SIZE"), output_file);
            } else {
                // Fallback: just replace the placeholder
                fprintf(output_file, "%zu", payload_size);
            }
        } else {
            // Copy line as-is
            fputs(line, output_file);
        }
    }
    
    fclose(template_file);
    fclose(output_file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <binary_path> <encryption_password>\n", argv[0]);
        return 1;
    }
    
    const char* binary_path = argv[1];
    const char* password = argv[2];
    
    // Read the binary file
    size_t binary_size;
    unsigned char* binary_data = read_file(binary_path, &binary_size);
    if (!binary_data) {
        fprintf(stderr, "Failed to read binary file: %s\n", binary_path);
        return 1;
    }
    
    // Encrypt the binary with the password
    RC4_CTX ctx;
    rc4_init(&ctx, (unsigned char*)password, strlen(password));
    rc4_crypt(&ctx, binary_data, binary_size);
    
    // Create the stub source code using template
    char stub_filename[] = "/tmp/binlocker_stub.c";
    if (process_template("stub_template.c", binary_data, binary_size, stub_filename) != 0) {
        fprintf(stderr, "Failed to process template\n");
        free(binary_data);
        return 1;
    }
    
    // Compile the stub with symbol stripping
    char compile_cmd[1024];
    snprintf(compile_cmd, sizeof(compile_cmd), "gcc -s -Os -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -Wl,--strip-all -o %s_protected %s", binary_path, stub_filename);
    
    printf("Compiling protected binary...\n");
    if (system(compile_cmd) != 0) {
        fprintf(stderr, "Failed to compile protected binary\n");
        unlink(stub_filename);
        free(binary_data);
        return 1;
    }
    
    printf("Protected binary created: %s_protected\n", binary_path);
    printf("Usage: %s_protected <decryption_password> [args...]\n", binary_path);
    
    // Cleanup
    unlink(stub_filename);
    free(binary_data);
    
    return 0;
}