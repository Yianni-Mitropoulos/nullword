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

#define VERSION        "NullWord v1.0"
#define HASHLEN        32
#define FINALPWLEN     16
#define DELIM          "::::::::::"
#define BASE36LEN      50
#define DIRNAME        ".nullword"
#define FILENAME       "creds.txt"
#define MAXNAME        64    // for first/last name (UTF-8 bytes)
#define MAXSERVICE     64    // for service name (UTF-8 bytes)
#define MAXPASS        64    // for master password (UTF-8 bytes)

#define ARGON2_T_COST_NORMAL 2
#define ARGON2_T_COST_BRUTAL 64
#define ARGON2_M_COST  1126400
#define ARGON2_P_COST  5

#define PEPPER_MAGIC "paddingpadding"
#define PEPPER_MAGIC_LEN (sizeof(PEPPER_MAGIC) - 1)

#define AES_KEYLEN 32
#define AES_IVLEN 16

#define BADCHAR_WARNING "\
| WARNING\n\
| 1. Your input contains capital letters, whitespace, or other fancy characters.\n\
| 2. We therefore recommend restarting the process from the beginning.\n\
| 3. We'll use your input as-is, without sanitizing it.\n\
| 4. But it's STRONGLY recommended that you avoid using fancy characters in your names.\n\
|    This is because you'll need to type the exact same names again in the future.\n\
|    Fancy characters can lead to frustration further down the track.\n"

void secure_memzero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

int has_bad_char(const char *str, size_t len) {
    int found = 0;
    for (size_t i = 0; i < len; ) {
        unsigned char c = str[i];
        if (c < 128) {
            if (isupper(c) || isspace(c) || (!isalpha(c) && !isdigit(c))) found = 1;
            ++i;
        } else {
            int clen = 1;
            if ((c & 0xE0) == 0xC0) clen = 2;
            else if ((c & 0xF0) == 0xE0) clen = 3;
            else if ((c & 0xF8) == 0xF0) clen = 4;
            i += clen;
        }
    }
    return found;
}

// UTF-8 safe line editor, returns length in bytes
size_t read_line(const char *prompt, unsigned char *buf, size_t maxlen, int mask, int *out_charlen) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t len = 0, pos = 0, charlen = 0;
    unsigned char input[maxlen + 5];
    input[0] = 0;

    while (1) {
        int c = getchar();

        if (c == '\n' || c == '\r')
            break;

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
                continue;
            }
        }

        // Backspace
        if ((c == 127 || c == 8) && pos > 0) {
            size_t orig = pos;
            do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
            memmove(&input[pos], &input[orig], len - orig + 1);
            len -= orig - pos;
            charlen--;
            printf("\033[1D\033[s");
            for (size_t i = pos; i < len; ) {
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
            input[len++] = c;
            if ((c & 0xE0) == 0xC0) { input[len++] = getchar(); }
            else if ((c & 0xF0) == 0xE0) { input[len++] = getchar(); input[len++] = getchar(); }
            else if ((c & 0xF8) == 0xF0) { input[len++] = getchar(); input[len++] = getchar(); input[len++] = getchar(); }
            printf("\033[s");
            if (mask) {
                for (size_t i = pos; i < len; ) { putchar('*');
                    size_t step = 1;
                    if ((input[i] & 0xE0) == 0xC0) step = 2;
                    else if ((input[i] & 0xF0) == 0xE0) step = 3;
                    else if ((input[i] & 0xF8) == 0xF0) step = 4;
                    i += step;
                }
            } else {
                for (size_t i = pos; i < len; ) {
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
            charlen++;
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
    if (out_charlen) *out_charlen = charlen;
    return len;
}

void print_argon2_error(int rc, const char *context) {
    fprintf(stderr, "Argon2 error in %s: %s\n", context, argon2_error_message(rc));
    switch (rc) {
        case ARGON2_OK: break;
        case ARGON2_MEMORY_TOO_LITTLE:
        case ARGON2_MEMORY_ALLOCATION_ERROR:
            fprintf(stderr, "-> Not enough memory for Argon2 hash computation.\n");
            break;
        case ARGON2_THREADS_TOO_FEW:
        case ARGON2_THREADS_TOO_MANY:
            fprintf(stderr, "-> Parallelism parameter is invalid or unsupported.\n");
            break;
        case ARGON2_PWD_TOO_SHORT:
        case ARGON2_PWD_TOO_LONG:
            fprintf(stderr, "-> Password parameter is invalid or unsupported length.\n");
            break;
        case ARGON2_SALT_TOO_SHORT:
        case ARGON2_SALT_TOO_LONG:
            fprintf(stderr, "-> Salt parameter is invalid or unsupported length.\n");
            break;
        default:
            fprintf(stderr, "-> Error code %d in context: %s\n", rc, context);
    }
}

int argon2id_hash_raw_params(int t_cost, int m_cost, int p_cost,
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
        print_argon2_error(rc, context);
    }
    return rc;
}

int try_clipboard(const char *cmd, const char *text) {
    FILE *clip = popen(cmd, "w");
    if (!clip)
        return 0;
    int rc = fprintf(clip, "%s", text);
    int status = pclose(clip);
    if (rc < 0 || status != 0)
        return 0;
    return 1;
}

int ensure_nullword_dir(const char *dirpath) {
    struct stat st;
    if (stat(dirpath, &st) == -1) {
        if (mkdir(dirpath, 0700) == -1) {
            fprintf(stderr, "Failed to create %s\n", dirpath);
            return 1;
        }
    }
    return 0;
}

int aes256_cbc_encrypt(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *plaintext, int plaintext_len,
                       unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ciphlen = 0;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    ciphlen = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    ciphlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphlen;
}

int aes256_cbc_decrypt(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *ciphertext, int ciphertext_len,
                       unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plainlen = 0;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }
    plainlen = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return plainlen; }
    plainlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return plainlen;
}

void base36_tailN(const unsigned char *in, char *out, int outlen) {
    unsigned char digits[HASHLEN+1] = {0};
    memcpy(digits+1, in, HASHLEN);
    char buf[BASE36LEN+1] = {0};
    int outpos = BASE36LEN;
    for(int i = 0; i < BASE36LEN; ++i) {
        int remainder = 0;
        for(int j = 0; j < HASHLEN+1; ++j) {
            int acc = (remainder << 8) + digits[j];
            digits[j] = acc / 36;
            remainder = acc % 36;
        }
        buf[--outpos] = (remainder < 10) ? ('0' + remainder) : ('a' + remainder-10);
    }
    buf[BASE36LEN] = 0;
    strncpy(out, buf + BASE36LEN - outlen, outlen);
    out[outlen] = 0;
}

int secure_delete_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        if (errno == ENOENT) {
            printf("No credentials file to delete.\n");
            return 0;
        } else {
            perror("Failed to stat credentials file");
            return 1;
        }
    }
    size_t size = st.st_size;
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open credentials file for secure deletion");
        return 1;
    }
    char zeros[4096] = {0};
    size_t written = 0;
    while (written < size) {
        size_t towrite = (size - written > sizeof(zeros)) ? sizeof(zeros) : size - written;
        ssize_t w = write(fd, zeros, towrite);
        if (w < 0 || (size_t)w != towrite) {
            perror("Failed to overwrite credentials file");
            close(fd);
            return 1;
        }
        written += towrite;
    }
    fsync(fd);
    close(fd);
    if (unlink(path) == 0) {
        printf("Credentials securely deleted. Bye!\n");
        return 0;
    } else {
        perror("Failed to delete credentials file");
        return 1;
    }
}

int main() {
    setlocale(LC_ALL, "");
    printf("%s | Argon2id params: t_cost_normal=%d, t_cost_brutal=%d, m_cost=%d, parallelism=%d\n",
           VERSION, ARGON2_T_COST_NORMAL, ARGON2_T_COST_BRUTAL, ARGON2_M_COST, ARGON2_P_COST);

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Could not find HOME environment variable.\n");
        return 1;
    }

    char dirpath[1024], credsfile[1024];
    size_t dirpathlen = snprintf(dirpath, sizeof(dirpath), "%s/%s", home, DIRNAME);
    if (dirpathlen >= sizeof(dirpath)) {
        fprintf(stderr, "Directory path too long!\n");
        return 1;
    }
    size_t credsfilelen = snprintf(credsfile, sizeof(credsfile), "%s/%s", dirpath, FILENAME);
    if (credsfilelen >= sizeof(credsfile)) {
        fprintf(stderr, "Credentials file path too long!\n");
        return 1;
    }

    unsigned char firstname[MAXNAME + 1] = {0};
    size_t fn_len = 0;

    unsigned char lastname_raw[MAXNAME + 1] = {0};
    size_t ln_raw_len = 0;
    unsigned char password[MAXPASS + 1] = {0};
    size_t pw_len = 0;
    unsigned char pepper[HASHLEN] = {0};
    unsigned char lastname[HASHLEN] = {0};
    unsigned char aes_iv[AES_IVLEN] = {0};
    unsigned char ciphertext[256] = {0};

    FILE *cf = fopen(credsfile, "rb");
    if (!cf) {
        printf("Welcome to NullWord. First-time setup.\n");
        printf("| REMARKS\n");
        printf("| 1. These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("| 2. They can be fake names, but you have to be consistent.\n");
        printf("| 3. Both are stored in encrypted form in %s\n", credsfile);

        fn_len = read_line("First name (used as salt): ", firstname, MAXNAME, 0, NULL);
        if (has_bad_char((char*)firstname, fn_len)) printf("%s", BADCHAR_WARNING);

        do {
            ln_raw_len = read_line("Last name (hidden, like a second password): ", lastname_raw, MAXNAME, 1, NULL);
            unsigned char confirm[MAXNAME + 1] = {0};
            size_t ln2 = read_line("Repeat last name: ", confirm, MAXNAME, 1, NULL);
            if (ln_raw_len != ln2 || memcmp(lastname_raw, confirm, ln_raw_len) != 0) {
                printf("Error: last names do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        do {
            pw_len = read_line("Master password: ", password, MAXPASS, 1, NULL);
            unsigned char confirm[MAXPASS + 1] = {0};
            size_t pw2 = read_line("Repeat master password: ", confirm, MAXPASS, 1, NULL);
            if (pw_len != pw2 || memcmp(password, confirm, pw_len) != 0) {
                printf("Error: passwords do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        printf("Deriving pepper. This may take 10-30 seconds on modern CPUs. On some older systems, it can take a minute or two.\n"
               "Please wait, expensive cryptography in progress...\n");

        unsigned char pepper_input[MAXNAME + sizeof(DELIM) + MAXPASS + 4] = {0};
        size_t pepper_input_len = 0;
        memcpy(pepper_input, lastname_raw, ln_raw_len); pepper_input_len += ln_raw_len;
        memcpy(pepper_input + pepper_input_len, DELIM, sizeof(DELIM) - 1); pepper_input_len += sizeof(DELIM) - 1;
        memcpy(pepper_input + pepper_input_len, password, pw_len); pepper_input_len += pw_len;

        int rc = argon2id_hash_raw_params(
            ARGON2_T_COST_BRUTAL, ARGON2_M_COST, ARGON2_P_COST,
            pepper_input, pepper_input_len,
            firstname, MAXNAME,
            pepper, HASHLEN,
            "derive pepper"
        );
        if (rc != ARGON2_OK) {
            secure_memzero(password, sizeof(password));
            secure_memzero(lastname_raw, sizeof(lastname_raw));
            secure_memzero(pepper, sizeof(pepper));
            return 2;
        }
        memcpy(lastname, pepper, HASHLEN);

        unsigned char secret[HASHLEN] = {0};
        rc = argon2id_hash_raw_params(
            ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
            password, pw_len,
            firstname, MAXNAME,
            secret, HASHLEN,
            "derive secret"
        );
        if (rc != ARGON2_OK) {
            secure_memzero(password, sizeof(password));
            secure_memzero(secret, sizeof(secret));
            return 2;
        }

        if (RAND_bytes(aes_iv, AES_IVLEN) != 1) {
            fprintf(stderr, "RAND_bytes() failed.\n");
            return 2;
        }
        unsigned char plaintext[PEPPER_MAGIC_LEN + HASHLEN] = {0};
        memcpy(plaintext, PEPPER_MAGIC, PEPPER_MAGIC_LEN);
        memcpy(plaintext + PEPPER_MAGIC_LEN, pepper, HASHLEN);

        int ciphlen = aes256_cbc_encrypt(secret, aes_iv, plaintext, sizeof(plaintext), ciphertext);
        if (ciphlen < 0) {
            fprintf(stderr, "AES encryption failed.\n");
            return 2;
        }

        if (ensure_nullword_dir(dirpath) != 0) return 2;
        umask(0077);

        cf = fopen(credsfile, "wb");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); return 2; }
        if (fwrite(firstname, 1, MAXNAME, cf) != MAXNAME ||
            fwrite(aes_iv, 1, AES_IVLEN, cf) != AES_IVLEN ||
            fwrite(ciphertext, 1, ciphlen, cf) != (size_t)ciphlen) {
            fprintf(stderr, "Failed to write credentials file.\n");
            fclose(cf);
            return 2;
        }
        fclose(cf);

        printf("Thanks, %s! Your credentials are now stored (encrypted) in %s\n\n", firstname, credsfile);
        secure_memzero(secret, sizeof(secret));
        secure_memzero(password, sizeof(password));
        secure_memzero(lastname_raw, sizeof(lastname_raw));
        secure_memzero(pepper, sizeof(pepper));
    } else {
        if (fread(firstname, 1, MAXNAME, cf) != MAXNAME) {
            fprintf(stderr, "Corrupt credentials file (firstname).\n");
            fclose(cf);
            secure_delete_file(credsfile);
            return 3;
        }
        if (fread(aes_iv, 1, AES_IVLEN, cf) != AES_IVLEN) {
            fprintf(stderr, "Corrupt credentials file (iv).\n");
            fclose(cf);
            secure_delete_file(credsfile);
            return 3;
        }
        size_t n_cipher = fread(ciphertext, 1, sizeof(ciphertext), cf);
        if (n_cipher == 0) {
            fprintf(stderr, "Corrupt credentials file (ciphertext).\n");
            fclose(cf);
            secure_delete_file(credsfile);
            return 3;
        }
        fclose(cf);

        printf("Hey, welcome back to NullWord.\n");
        printf("| REMARKS\n");
        printf("| 1. Your credentials file is stored at %s\n", credsfile);
        printf("| 2. You can use a service name of 'logout' to delete your credentials file.\n");
    }

    unsigned char service[MAXSERVICE + 1] = {0};
    size_t svc_len = read_line("Service name: ", service, MAXSERVICE, 0, NULL);
    if (has_bad_char((char*)service, svc_len)) printf("%s", BADCHAR_WARNING);

    if (svc_len == 6 && memcmp(service, "logout", 6) == 0) {
        secure_memzero(firstname, sizeof(firstname));
        secure_memzero(service, sizeof(service));
        return secure_delete_file(credsfile);
    }

    size_t pw_len2 = read_line("Master password: ", password, MAXPASS, 1, NULL);

    unsigned char secret[HASHLEN] = {0};
    int rc = argon2id_hash_raw_params(
        ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
        password, pw_len2,
        firstname, MAXNAME,
        secret, HASHLEN,
        "derive secret"
    );
    if (rc != ARGON2_OK) {
        secure_memzero(secret, sizeof(secret));
        secure_memzero(password, sizeof(password));
        fprintf(stderr, "Could not derive secret.\n");
        return 2;
    }

    unsigned char decrypted[PEPPER_MAGIC_LEN + HASHLEN + 16] = {0};
    int decrypted_len = aes256_cbc_decrypt(secret, aes_iv, ciphertext, sizeof(ciphertext), decrypted);

    int valid_pepper = 0;
    if ((decrypted_len >= (int)(PEPPER_MAGIC_LEN + HASHLEN)) &&
        memcmp(decrypted, PEPPER_MAGIC, PEPPER_MAGIC_LEN) == 0) {
        valid_pepper = 1;
    }
    if (!valid_pepper) {
        printf("| WARNING\n");
        printf("| Wrong password!\n");
        printf("| We'll use whatever came out of decryption anyway.\n");
    }

    unsigned char pepper_for_hash[PEPPER_MAGIC_LEN + HASHLEN] = {0};
    memcpy(pepper_for_hash, decrypted, PEPPER_MAGIC_LEN + HASHLEN);

    unsigned char combined[MAXSERVICE + 1 + 3 + MAXPASS + 1 + PEPPER_MAGIC_LEN + HASHLEN + 8] = {0};
    size_t offset = 0;
    memcpy(combined, service, svc_len); offset += svc_len;
    memcpy(combined + offset, DELIM, sizeof(DELIM) - 1); offset += sizeof(DELIM) - 1;
    memcpy(combined + offset, password, pw_len2); offset += pw_len2;
    memcpy(combined + offset, DELIM, sizeof(DELIM) - 1); offset += sizeof(DELIM) - 1;
    memcpy(combined + offset, pepper_for_hash, PEPPER_MAGIC_LEN + HASHLEN); offset += PEPPER_MAGIC_LEN + HASHLEN;

    unsigned char out_hash[HASHLEN] = {0};
    rc = argon2id_hash_raw_params(
        ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
        combined, offset,
        firstname, MAXNAME,
        out_hash, HASHLEN,
        "final password"
    );
    if (rc != ARGON2_OK) {
        fprintf(stderr, "Failed to derive service password.\n");
        return 2;
    }

    char outpw[FINALPWLEN + 1] = {0};
    base36_tailN(out_hash, outpw, FINALPWLEN);

    int copied = 0;
    copied = try_clipboard("xclip -selection clipboard 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("xsel --clipboard --input 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("wl-copy 2>/dev/null", outpw);

    if (copied) {
        printf("Password copied to clipboard!\n");
    } else {
        printf("Could not copy password to clipboard.\n");
        printf("Please install xclip, xsel, or wl-clipboard to enable clipboard copy.\n");
        printf("For your security, nullword will never print your password to the terminal.\n");
    }

    // Zero sensitive memory
    secure_memzero(secret, sizeof(secret));
    secure_memzero(password, sizeof(password));
    secure_memzero(decrypted, sizeof(decrypted));
    secure_memzero(out_hash, sizeof(out_hash));
    secure_memzero(outpw, sizeof(outpw));
    secure_memzero(service, sizeof(service));
    secure_memzero(firstname, sizeof(firstname));
    secure_memzero(lastname, sizeof(lastname));
    secure_memzero(pepper, sizeof(pepper));
    secure_memzero(aes_iv, sizeof(aes_iv));
    secure_memzero(ciphertext, sizeof(ciphertext));
    secure_memzero(lastname_raw, sizeof(lastname_raw));
    return 0;
}
