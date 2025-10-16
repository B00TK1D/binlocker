# Binlocker

A binary encryption tool that protects executables with password-based RC4 encryption. The protected binary never touches disk during execution (only runs in memory).


## Usage

### Compile
```bash
make
```

### Protect a Binary
```bash
./binlocker <binary_path> <encryption_password>
```

### Run Protected Binary
```bash
./<binary_path>_protected <decryption_password> [args...]
```

## Example

```bash
# Create a test program
echo 'int main() { printf("Hello World!\n"); return 0; }' > hello.c
gcc -o hello hello.c

# Protect it
./binlocker hello mypassword

# Run the protected binary
./hello_protected mypassword
```