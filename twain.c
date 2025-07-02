// twain.c - TwainPass: Deterministic password manager (production ready)
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <argon2.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#define VERSION        "TwainPass v1.0"
#define HASHLEN        32
#define FINALPWLEN     16
#define DELIM          "::::::::::"
#define DIRNAME        ".twain"
#define FILENAME       "creds.txt"
#define MAXNAME        16     // for first name (UTF-8 bytes, not chars; 16 bytes to fit AES IV)
#define MAXPASS        64     // for master password (UTF-8 bytes)
#define MAXPHRASE      512    // for passphrase (UTF-8 bytes)
#define AES_KEYLEN     32
#define AES_IVLEN      16
#define ARGON2_T_COST_NORMAL 2
#define ARGON2_T_COST_BRUTAL 64
#define ARGON2_M_COST  1126400
#define ARGON2_P_COST  5

#define PEPPER_MAGIC   "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // 32 x's
#define PEPPER_MAGIC_LEN (sizeof(PEPPER_MAGIC)-1)
#define PEPPER_LEN (PEPPER_MAGIC_LEN + HASHLEN)

#define BADCHAR_WARNING "\
| WARNING\n\
| 1. Your input contains capital letters, whitespace, or other fancy characters.\n\
| 2. We therefore recommend restarting the process from the beginning.\n\
| 3. We'll use your input as-is, without sanitizing it.\n\
| 4. But it's STRONGLY recommended that you avoid using fancy characters in your names or services.\n\
|    This is because you'll need to type the exact same names again in the future.\n\
|    Fancy characters can lead to frustration further down the track.\n"

// Securely zero memory
void secure_memzero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

// Returns 1 if str contains uppercase, whitespace, or punctuation
int has_bad_char(const char *str, size_t len) {
    int found = 0;
    for (size_t i = 0; i < len;) {
        unsigned char c = (unsigned char)str[i];
        if (c < 128) {
            if (isupper(c) || isspace(c) || (!isalpha(c) && !isdigit(c))) found = 1;
            ++i;
        } else {
            // Accept all multibyte UTF-8
            if ((c & 0xE0) == 0xC0) i += 2;
            else if ((c & 0xF0) == 0xE0) i += 3;
            else if ((c & 0xF8) == 0xF0) i += 4;
            else i += 1;
        }
    }
    return found;
}

// Returns length in bytes. Sets *out_num_chars if non-NULL.
size_t read_line(const char *prompt, unsigned char *buf, size_t maxlen, int mask, size_t *out_num_chars) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t len = 0, pos = 0, num_chars = 0;
    unsigned char input[maxlen + 8]; // Room for utf-8 safety
    input[0] = 0;

    while (1) {
        int c = getchar();

        // ENTER
        if (c == '\n' || c == '\r') break;

        // Arrow keys: left/right (optional, very basic, only move cursor)
        if (c == 27) { // ESC
            int c2 = getchar();
            if (c2 == '[') {
                int c3 = getchar();
                // Left
                if (c3 == 'D' && pos > 0) {
                    do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
                    printf("\033[1D");
                    fflush(stdout);
                }
                // Right
                else if (c3 == 'C' && pos < len) {
                    size_t next = pos+1;
                    while (next < len && (input[next] & 0xC0) == 0x80) ++next;
                    if (next <= len) {
                        printf("\033[1C");
                        pos = next;
                        fflush(stdout);
                    }
                }
                // Delete key: ESC [ 3 ~
                else if (c3 == '3') {
                    int c4 = getchar(); // should be '~'
                    if (c4 == '~' && pos < len) {
                        // Delete char at cursor
                        size_t delbytes = 1;
                        if ((input[pos] & 0xE0) == 0xC0) delbytes = 2;
                        else if ((input[pos] & 0xF0) == 0xE0) delbytes = 3;
                        else if ((input[pos] & 0xF8) == 0xF0) delbytes = 4;
                        memmove(&input[pos], &input[pos + delbytes], len - pos - delbytes + 1);
                        len -= delbytes;
                        printf("\033[s");
                        for (size_t i = pos; i < len;) {
                            if (mask) putchar('*');
                            else {
                                int clen = 1;
                                if ((input[i] & 0xE0) == 0xC0) clen = 2;
                                else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                                else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                                fwrite(&input[i], 1, clen, stdout);
                            }
                            size_t step = 1;
                            if ((input[i] & 0xE0) == 0xC0) step = 2;
                            else if ((input[i] & 0xF0) == 0xE0) step = 3;
                            else if ((input[i] & 0xF8) == 0xF0) step = 4;
                            i += step;
                        }
                        putchar(' ');
                        printf("\033[u");
                        fflush(stdout);
                    }
                }
                continue;
            }
        }

        // Backspace (127 or 8)
        if ((c == 127 || c == 8)) {
            if (pos == 0) continue; // do nothing at leftmost
            size_t orig = pos;
            do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
            memmove(&input[pos], &input[orig], len - orig + 1);
            len -= orig - pos;
            num_chars--;
            printf("\033[1D\033[s");
            for (size_t i = pos; i < len;) {
                if (mask) putchar('*');
                else {
                    int clen = 1;
                    if ((input[i] & 0xE0) == 0xC0) clen = 2;
                    else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                    else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                    fwrite(&input[i], 1, clen, stdout);
                }
                size_t step = 1;
                if ((input[i] & 0xE0) == 0xC0) step = 2;
                else if ((input[i] & 0xF0) == 0xE0) step = 3;
                else if ((input[i] & 0xF8) == 0xF0) step = 4;
                i += step;
            }
            putchar(' ');
            printf("\033[u");
            fflush(stdout);
            continue;
        }

        // Insert char
        if ((unsigned char)c >= 32 && len + 4 < maxlen) {
            int cbytes = 1;
            if ((c & 0xE0) == 0xC0) cbytes = 2;
            else if ((c & 0xF0) == 0xE0) cbytes = 3;
            else if ((c & 0xF8) == 0xF0) cbytes = 4;
            if (len + cbytes >= maxlen) continue;
            input[len++] = c;
            for (int k = 1; k < cbytes; ++k)
                input[len++] = getchar();
            printf("\033[s");
            if (mask) {
                for (size_t i = pos; i < len;) {
                    putchar('*');
                    size_t step = 1;
                    if ((input[i] & 0xE0) == 0xC0) step = 2;
                    else if ((input[i] & 0xF0) == 0xE0) step = 3;
                    else if ((input[i] & 0xF8) == 0xF0) step = 4;
                    i += step;
                }
            } else {
                for (size_t i = pos; i < len;) {
                    int clen = 1;
                    if ((input[i] & 0xE0) == 0xC0) clen = 2;
                    else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                    else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                    fwrite(&input[i], 1, clen, stdout);
                    i += clen;
                }
            }
            putchar(' ');
            printf("\033[u");
            printf("\033[1C");
            fflush(stdout);
            pos = len;
            num_chars++;
        }
    }
    input[len] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    if (len >= maxlen) {
        fprintf(stderr, "Input too long! (max %zu bytes)\n", maxlen - 1);
        exit(1);
    }
    memcpy(buf, input, len);
    buf[len] = 0;
    if (out_num_chars) *out_num_chars = num_chars;
    return len;
}

// AES-256-CBC encrypt. Returns ciphertext len or -1.
int aes256_cbc_encrypt(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *plaintext, int plaintext_len,
                       unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ciphlen = 0;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphlen = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphlen;
}

// AES-256-CBC decrypt. Returns plaintext len or -1.
int aes256_cbc_decrypt(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *ciphertext, int ciphertext_len,
                       unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ptlen = 0;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ptlen = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ptlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ptlen;
}

int argon2id_hash_raw_params(
        uint32_t t_cost, uint32_t m_cost, uint32_t p_cost,
        const void *pwd, size_t pwdlen,
        const void *salt, size_t saltlen,
        void *hash, size_t hashlen,
        const char *context) {
    int rc = argon2id_hash_raw(
        t_cost, m_cost, p_cost,
        pwd, pwdlen,
        salt, saltlen,
        hash, hashlen);
    if (rc != ARGON2_OK) {
        fprintf(stderr, "Argon2 error in %s: %s\n", context, argon2_error_message(rc));
        if (rc == ARGON2_SALT_TOO_SHORT)
            fprintf(stderr, "-> Salt parameter is invalid or unsupported length.\n-> Context: %s\n", context);
        else if (rc == ARGON2_MEMORY_TOO_LITTLE || rc == ARGON2_MEMORY_ALLOCATION_ERROR)
            fprintf(stderr, "-> Not enough memory for Argon2 computation.\n");
        else
            fprintf(stderr, "-> Argon2 context: %s\n", context);
    }
    return rc;
}

int ensure_twain_dir(const char *dirpath) {
    struct stat st;
    if (stat(dirpath, &st) == -1) {
        if (mkdir(dirpath, 0700) == -1) {
            fprintf(stderr, "Failed to create %s\n", dirpath);
            return 1;
        }
    }
    return 0;
}

void base36_tailN(const unsigned char *in, char *out, int outlen) {
    unsigned char digits[HASHLEN+1] = {0};
    memcpy(digits+1, in, HASHLEN);

    char buf[80] = {0};
    int outpos = 79;

    for(int i = 0; i < 79; ++i) {
        int remainder = 0;
        for(int j = 0; j < HASHLEN+1; ++j) {
            int acc = (remainder << 8) + digits[j];
            digits[j] = acc / 36;
            remainder = acc % 36;
        }
        buf[--outpos] = (remainder < 10) ? ('0' + remainder) : ('a' + remainder-10);
    }
    buf[79] = 0;
    strncpy(out, buf + 79 - outlen, outlen);
    out[outlen] = 0;
}

int try_clipboard(const char *cmd, const char *text) {
    FILE *clip = popen(cmd, "w");
    if (!clip) return 0;
    int rc = fprintf(clip, "%s", text);
    int status = pclose(clip);
    if (rc < 0 || status != 0) return 0;
    return 1;
}

int main() {
    setlocale(LC_ALL, "");
    ERR_load_crypto_strings();
    printf("%s | Argon2id params: t_cost_normal=%d, t_cost_brutal=%d, m_cost=%d, parallelism=%d\n",
        VERSION, ARGON2_T_COST_NORMAL, ARGON2_T_COST_BRUTAL, ARGON2_M_COST, ARGON2_P_COST);
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

    const char *home = getenv("HOME");
    if (!home) { fprintf(stderr, "Could not find HOME environment variable.\n"); return 1; }

    char dirpath[1024], credsfile[1024];
    int dlen = snprintf(dirpath, sizeof(dirpath), "%s/%s", home, DIRNAME);
    if (dlen < 0 || (size_t)dlen >= sizeof(dirpath)) {
        fprintf(stderr, "Directory path too long!\n");
        return 1;
    }
    int clen = snprintf(credsfile, sizeof(credsfile), "%s/%s", dirpath, FILENAME);
    if (clen < 0 || (size_t)clen >= sizeof(credsfile)) {
        fprintf(stderr, "Credentials file path too long!\n");
        return 1;
    }

    unsigned char firstname[MAXNAME+1] = {0};   // 16 bytes + nul
    unsigned char passphrase[MAXPHRASE+1] = {0};
    unsigned char password[MAXPASS+1] = {0};
    unsigned char pepper[PEPPER_LEN] = {0};
    unsigned char aes_iv[AES_IVLEN] = {0};

    FILE *cf = fopen(credsfile, "rb");
    if (!cf) {
        printf("Welcome to TwainPass. First-time setup.\n");
        printf("| REMARKS\n");
        printf("| 1. These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("| 2. They can be fake, but you have to be consistent.\n");
        printf("| 3. Both are stored in encrypted form in %s\n", credsfile);

        size_t fn_len = read_line("First name (used as salt, max 16 chars): ", firstname, MAXNAME, 0, NULL);
        if (has_bad_char((char*)firstname, fn_len)) printf("%s", BADCHAR_WARNING);

        size_t ph_len = 0;
        do {
            ph_len = read_line("Passphrase (hidden, like a second password): ", passphrase, MAXPHRASE, 1, NULL);
            unsigned char confirm[MAXPHRASE+1] = {0};
            size_t ph2 = read_line("Repeat passphrase: ", confirm, MAXPHRASE, 1, NULL);
            if (ph_len != ph2 || memcmp(passphrase, confirm, ph_len) != 0) {
                printf("Error: passphrases do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        size_t pw_len = 0;
        do {
            pw_len = read_line("Master password: ", password, MAXPASS, 1, NULL);
            unsigned char confirm[MAXPASS+1] = {0};
            size_t pw2 = read_line("Repeat master password: ", confirm, MAXPASS, 1, NULL);
            if (pw_len != pw2 || memcmp(password, confirm, pw_len) != 0) {
                printf("Error: passwords do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        printf("Deriving pepper. This may take 10-30 seconds on modern CPUs. On some older systems, it can take a minute or two.\n"
               "Please wait, expensive cryptography in progress...\n");

        unsigned char fname_salt[MAXNAME] = {0}; memcpy(fname_salt, firstname, fn_len);

        unsigned char pepper_input[MAXPHRASE + sizeof(DELIM) + MAXPASS] = {0};
        size_t offset = 0;
        memcpy(pepper_input, passphrase, ph_len); offset += ph_len;
        memcpy(pepper_input+offset, DELIM, sizeof(DELIM)-1); offset += sizeof(DELIM)-1;
        memcpy(pepper_input+offset, password, pw_len); offset += pw_len;

        unsigned char pepper_hash[HASHLEN] = {0};
        { int rc = argon2id_hash_raw_params(
            ARGON2_T_COST_BRUTAL, ARGON2_M_COST, ARGON2_P_COST,
            pepper_input, offset,
            fname_salt, MAXNAME,
            pepper_hash, HASHLEN,
            "derive pepper"
        );
        if (rc != ARGON2_OK) {
            secure_memzero(password, sizeof(password));
            secure_memzero(passphrase, sizeof(passphrase));
            return 2;
        }}

        memcpy(pepper, PEPPER_MAGIC, PEPPER_MAGIC_LEN);
        memcpy(pepper+PEPPER_MAGIC_LEN, pepper_hash, HASHLEN);

        unsigned char secret[HASHLEN] = {0};
        { int rc = argon2id_hash_raw_params(
            ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
            password, pw_len,
            fname_salt, MAXNAME,
            secret, HASHLEN,
            "derive secret"
        );
        if (rc != ARGON2_OK) {
            secure_memzero(password, sizeof(password));
            secure_memzero(secret, sizeof(secret));
            return 2;
        }}

        memcpy(aes_iv, fname_salt, AES_IVLEN);

        unsigned char ciphertext[PEPPER_LEN + AES_IVLEN] = {0};
        int ciphlen = aes256_cbc_encrypt(secret, aes_iv, pepper, PEPPER_LEN, ciphertext);
        if (ciphlen < 0) {
            fprintf(stderr, "AES encryption failed.\n");
            ERR_print_errors_fp(stderr);
            return 2;
        }

        if (ensure_twain_dir(dirpath) != 0) return 2;
        umask(0077);

        cf = fopen(credsfile, "wb");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); return 2; }
        if (fwrite(firstname, 1, fn_len, cf) != fn_len || // Write without padding, but with EOL after
            fputc('\n', cf) == EOF ||
            fwrite(ciphertext, 1, ciphlen, cf) != (size_t)ciphlen) {
            fprintf(stderr, "Failed to write credentials file.\n");
            fclose(cf);
            return 2;
        }
        fclose(cf);

        printf("Thanks! Your credentials are now stored (encrypted) in %s\n", credsfile);
        secure_memzero(secret, sizeof(secret));
        secure_memzero(pepper, sizeof(pepper));
        secure_memzero(password, sizeof(password));
        secure_memzero(passphrase, sizeof(passphrase));
        return 0;
    }

    // --- Main workflow ---
    unsigned char fname_file[MAXNAME+2] = {0};
    size_t fn_len = 0;
    if (!fgets((char*)fname_file, sizeof(fname_file), cf)) {
        fprintf(stderr, "Failed to read first name from credentials file.\n");
        fclose(cf);
        return 2;
    }
    fn_len = strcspn((char*)fname_file, "\r\n");
    unsigned char fname_salt[MAXNAME] = {0};
    memcpy(fname_salt, fname_file, fn_len > MAXNAME ? MAXNAME : fn_len);
    memcpy(aes_iv, fname_salt, AES_IVLEN);

    unsigned char ciphertext[PEPPER_LEN + AES_IVLEN] = {0};
    size_t ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), cf);
    fclose(cf);

    unsigned char secret[HASHLEN] = {0};
    unsigned char pepper_decrypted[PEPPER_LEN + 16] = {0};
    int decrypted_len = 0;
    char service[128] = {0};

    printf("Hey, welcome back to TwainPass.\n");
    printf("| REMARKS\n");
    printf("| 1. Your credentials file is stored at %s\n", credsfile);
    printf("| 2. You can use a service name of 'logout' to delete your credentials file.\n\n");

    size_t service_len = read_line("Service name: ", (unsigned char*)service, sizeof(service)-1, 0, NULL);
    if (has_bad_char(service, service_len)) printf("%s", BADCHAR_WARNING);

    if (strcmp(service, "logout") == 0) {
        memset(secret, 0, sizeof(secret));
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(fname_salt, 0, sizeof(fname_salt));
        memset(fname_file, 0, sizeof(fname_file));
        if (unlink(credsfile) == 0)
            printf("Credentials securely deleted. Bye!\n");
        else
            perror("Failed to delete credentials file");
        return 0;
    }

    size_t pw_len = read_line("Master password: ", password, MAXPASS, 1, NULL);

    { int rc = argon2id_hash_raw_params(
        ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
        password, pw_len,
        fname_salt, MAXNAME,
        secret, HASHLEN,
        "derive secret"
    );
    if (rc != ARGON2_OK) {
        memset(password, 0, sizeof(password));
        memset(secret, 0, sizeof(secret));
        return 2;
    }}

    decrypted_len = aes256_cbc_decrypt(secret, aes_iv, ciphertext, ciphertext_len, pepper_decrypted);
    if (decrypted_len != PEPPER_LEN || memcmp(pepper_decrypted, PEPPER_MAGIC, PEPPER_MAGIC_LEN) != 0) {
        printf("| WARNING: Could not verify master password. Output is still deterministic.\n");
    }

    // Generate output password: Argon2id(salt=fname_salt, msg=service||DELIM||pepper, normal)
    unsigned char out_input[sizeof(service)+sizeof(DELIM)+PEPPER_LEN] = {0};
    size_t off = 0;
    memcpy(out_input, service, service_len); off += service_len;
    memcpy(out_input+off, DELIM, sizeof(DELIM)-1); off += sizeof(DELIM)-1;
    memcpy(out_input+off, pepper_decrypted, decrypted_len); off += decrypted_len;

    unsigned char out_hash[HASHLEN] = {0};
    { int rc = argon2id_hash_raw_params(
        ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
        out_input, off,
        fname_salt, MAXNAME,
        out_hash, HASHLEN,
        "final password derive"
    );
    if (rc != ARGON2_OK) {
        memset(secret, 0, sizeof(secret));
        memset(password, 0, sizeof(password));
        return 2;
    }}

    char outpw[FINALPWLEN+1] = {0};
    base36_tailN(out_hash, outpw, FINALPWLEN);

    int copied = 0;
    copied = try_clipboard("xclip -selection clipboard 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("xsel --clipboard --input 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("wl-copy 2>/dev/null", outpw);

    // Spawn clipboard clearer (twain-clip) if copy succeeded
    if (copied) {
        printf("Password copied to clipboard!\n");

        // Fork and exec twain-clip with the password as argument
        pid_t pid = fork();
        if (pid == 0) {
            // In child process
            char *argv[3] = {"twain-clip", outpw, NULL};
            execvp("twain-clip", argv);
            printf("If it's still lurking in the clipboard in 15 seconds, we'll clear the clipboard.\n");

            _exit(0);
        } else {
            printf("There was an issue spawning the process that's meant to clear the clipboard after 15 seconds.\n");
        }
    } else {
        printf("Could not copy password to clipboard.\n");
        printf("Please install xclip, xsel, or wl-clipboard to enable clipboard copy.\n");
        printf("For your security, TwainPass will never print your password to the terminal.\n");
    }

    secure_memzero(secret, sizeof(secret));
    secure_memzero(password, sizeof(password));
    secure_memzero(pepper_decrypted, sizeof(pepper_decrypted));
    secure_memzero(out_hash, sizeof(out_hash));
    secure_memzero(outpw, sizeof(outpw));
    secure_memzero(service, sizeof(service));
    secure_memzero(fname_salt, sizeof(fname_salt));

    return 0;
}
