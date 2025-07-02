// twain.c - TwainPass: Deterministic Password Manager (Production Build)
//
// Features:
//  - Deterministic password derivation from name, passphrase, master password, and service name
//  - Zero-knowledge: no master password or passphrase is ever stored in plaintext
//  - Service-name password copy, clipboard auto-clear (with "twain-clip" helper)
//  - Export ("creds-view") and permanent wipe ("creds-delete") of credentials
//  - Strong UTF-8 and edit support for names/services, strong error checking everywhere
//  - Robust secure memory erasure and secure exit handling
//
// Credentials file layout:
//   first_name \n AES(passphrase \n pepper)
//   - AES key = Argon2id(master_password, salt=first_name_padded, params=strong)
//   - IV      = first_name padded to 16 bytes (AES block size)
//   - pepper  = PEPPER_MAGIC (32 x's) + Argon2id(passphrase || DELIM || master_password, brutal params)
//   - DELIM   = "::::::::::" (10 colons, safe in UTF-8, never typed by user)

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
#include <openssl/sha.h>
#include <signal.h>
#include <sys/wait.h>

// ==== CONFIGURABLE CONSTANTS ====

#define VERSION        "TwainPass v1.0"
#define HASHLEN        32         // bytes output by Argon2id and SHA3-256
#define FINALPWLEN     16         // length of final output password (base36)
#define DELIM          "::::::::::" // Delimiter for hashing, never input by user
#define DIRNAME        ".twain"
#define FILENAME       "creds.txt"
#define MAXNAME        16         // first name, max 16 bytes (UTF-8), fits AES IV (128-bit)
#define MAXPASS        64         // master password max bytes (UTF-8)
#define MINPASS        16         // min password length (security)
#define MAXPHRASE      512        // passphrase max bytes (UTF-8)
#define MINPHRASE      3          // min passphrase length
#define AES_KEYLEN     32         // 256-bit AES
#define AES_IVLEN      16         // 128-bit IV
#define ARGON2_T_COST_NORMAL 2    // Argon2id "normal" time cost
#define ARGON2_T_COST_BRUTAL 64   // Argon2id "brutal" time cost
#define ARGON2_M_COST  1126400    // Argon2id memory cost (bytes/1024 = KiB)
#define ARGON2_P_COST  5          // Argon2id parallelism (threads)

// "Pepper" is 32 x's (magic), then 32-byte Argon2id hash (so 64 bytes total)
#define PEPPER_MAGIC   "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define PEPPER_MAGIC_LEN (sizeof(PEPPER_MAGIC)-1)
#define PEPPER_LEN (PEPPER_MAGIC_LEN + HASHLEN)

#define BADCHAR_WARNING "\
WARNINGS\n\
| 1. Your input contains capital letters, whitespace, or other fancy characters.\n\
| 2. We therefore recommend restarting the process from the beginning.\n\
| 3. We'll use your input as-is, without sanitizing it.\n\
| 4. But it's STRONGLY recommended that you avoid using fancy characters in your names or services.\n\
|    This is because you'll need to type the exact same names again in the future.\n\
|    Fancy characters can lead to frustration further down the track.\n"

// ==== SECURE MEMORY WIPE & EXIT STRATEGY ====

void secure_memzero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

// Always use secure_bail for any exit/quit/error to guarantee zeroing secrets
void secure_bail(int code,
    unsigned char *a, size_t alen,
    unsigned char *b, size_t blen,
    unsigned char *c, size_t clen,
    unsigned char *d, size_t dlen,
    unsigned char *e, size_t elen)
{
    if (a && alen) secure_memzero(a, alen);
    if (b && blen) secure_memzero(b, blen);
    if (c && clen) secure_memzero(c, clen);
    if (d && dlen) secure_memzero(d, dlen);
    if (e && elen) secure_memzero(e, elen);
    printf("\n");
    exit(code);
}

void secure_bail_simple(int code) {
    printf("\n");
    exit(code);
}

// ==== INPUT VALIDATION & UTF-8 FRIENDLY INTERACTIVE INPUT ====

// Returns 1 if string contains uppercase, whitespace, or non-alphanum ASCII
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

// Reads an input line with full UTF-8/cursor/edit support. (mask==1: hidden, mask==0: live edit)
// For masked: no echo at all (cursor appears stationary), for non-masked: full cursor.
size_t read_line(const char *prompt, unsigned char *buf, size_t maxlen, int mask, size_t *out_num_chars) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t len = 0, pos = 0, num_chars = 0;
    unsigned char input[maxlen + 8];
    input[0] = 0;

    while (1) {
        int c = getchar();
        if (c == '\n' || c == '\r') break;

        if (c == 27) {
            int c2 = getchar();
            if (c2 == '[') {
                int c3 = getchar();
                if (!mask) {
                    if (c3 == 'D' && pos > 0) {
                        do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
                        printf("\033[1D"); fflush(stdout);
                    }
                    else if (c3 == 'C' && pos < len) {
                        size_t next = pos+1;
                        while (next < len && (input[next] & 0xC0) == 0x80) ++next;
                        if (next <= len) {
                            printf("\033[1C"); fflush(stdout);
                            pos = next;
                        }
                    }
                    else if (c3 == '3') {
                        (void)getchar(); // '~'
                        if (pos < len) {
                            size_t delbytes = 1;
                            if ((input[pos] & 0xE0) == 0xC0) delbytes = 2;
                            else if ((input[pos] & 0xF0) == 0xE0) delbytes = 3;
                            else if ((input[pos] & 0xF8) == 0xF0) delbytes = 4;
                            memmove(&input[pos], &input[pos + delbytes], len - pos - delbytes + 1);
                            len -= delbytes;
                            printf("\033[s");
                            for (size_t i = pos; i < len;) {
                                int clen = 1;
                                if ((input[i] & 0xE0) == 0xC0) clen = 2;
                                else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                                else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                                fwrite(&input[i], 1, clen, stdout);
                                i += clen;
                            }
                            putchar(' ');
                            printf("\033[u");
                            fflush(stdout);
                        }
                    }
                }
                continue;
            }
        }

        if ((c == 127 || c == 8)) {
            if (pos == 0) continue;
            size_t orig = pos;
            do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
            size_t bwidth = orig - pos;
            memmove(&input[pos], &input[orig], len - orig + 1);
            len -= bwidth;
            num_chars--;
            if (!mask) {
                printf("\033[1D\033[s");
                for (size_t i = pos; i < len;) {
                    int clen = 1;
                    if ((input[i] & 0xE0) == 0xC0) clen = 2;
                    else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                    else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                    fwrite(&input[i], 1, clen, stdout);
                    i += clen;
                }
                putchar(' ');
                printf("\033[u");
                fflush(stdout);
            }
            continue;
        }

        if ((unsigned char)c >= 32 && len + 4 < maxlen) {
            int cbytes = 1;
            if ((c & 0xE0) == 0xC0) cbytes = 2;
            else if ((c & 0xF0) == 0xE0) cbytes = 3;
            else if ((c & 0xF8) == 0xF0) cbytes = 4;
            if (len + cbytes >= maxlen) continue;
            memmove(&input[pos + cbytes], &input[pos], len - pos + 1);
            input[pos] = c;
            for (int k = 1; k < cbytes; ++k)
                input[pos + k] = getchar();
            len += cbytes;
            if (!mask) {
                printf("\033[s");
                for (size_t i = pos; i < len;) {
                    int clen = 1;
                    if ((input[i] & 0xE0) == 0xC0) clen = 2;
                    else if ((input[i] & 0xF0) == 0xE0) clen = 3;
                    else if ((input[i] & 0xF8) == 0xF0) clen = 4;
                    fwrite(&input[i], 1, clen, stdout);
                    i += clen;
                }
                putchar(' ');
                printf("\033[u");
                printf("\033[1C");
                fflush(stdout);
            }
            pos += cbytes;
            num_chars++;
        }
    }
    input[len] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    if (!mask) printf("\n");

    if (len >= maxlen) {
        fprintf(stderr, "Input too long! (max %zu bytes)\n", maxlen - 1);
        secure_bail_simple(1);
    }
    memcpy(buf, input, len);
    buf[len] = 0;
    if (out_num_chars) *out_num_chars = num_chars;
    return len;
}

// ==== CRYPTOGRAPHIC ROUTINES ====

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
        return ptlen;
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

// ==== FILESYSTEM/CLIPBOARD UTILS ====

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

// Convert binary to lower-case hex (for pepper digest backup)
void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[2*i] = hex[(in[i]>>4)&0xF];
        out[2*i+1] = hex[in[i]&0xF];
    }
    out[2*len] = 0;
}

// Base36 (tail N chars) password encoding (guaranteed deterministic from hash)
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

// Attempts to copy text to clipboard using multiple tools (xclip, xsel, wl-copy)
int try_clipboard(const char *cmd, const char *text) {
    FILE *clip = popen(cmd, "w");
    if (!clip) return 0;
    int rc = fprintf(clip, "%s", text);
    int status = pclose(clip);
    if (rc < 0 || status != 0) return 0;
    return 1;
}

// Kills all running twain-clip clipboard-clear helper processes before new copy
void kill_old_twain_clip() {
    pid_t pid = fork();
    if (pid == 0) {
        execlp("pkill", "pkill", "-9", "-x", "twain-clip", (char*)NULL);
        _exit(0);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

/**
 * Find pointer to first newline '\n' in buf (of length buflen),
 * but only if at least PEPPER_MAGIC_LEN bytes follow the newline and
 * they match PEPPER_MAGIC exactly. Returns pointer to '\n', or NULL if not found/matching.
 */
char* find_newline_with_pepper_magic(unsigned char *buf, size_t buflen) {
    for (size_t i = 0; i < buflen; ++i) {
        if (buf[i] == '\n') {
            // Check that enough bytes remain for PEPPER_MAGIC
            if ((buflen - (i + 1)) >= PEPPER_MAGIC_LEN &&
                memcmp(buf + i + 1, PEPPER_MAGIC, PEPPER_MAGIC_LEN) == 0) {
                return (char*)buf + i; // pointer to '\n'
            }
            break; // Found newline, but no/invalid magic after
        }
    }
    return NULL;
}

// ==== MAIN LOGIC: Setup, Normal use, creds-delete, creds-view ====

int main() {
    setlocale(LC_ALL, "");
    ERR_load_crypto_strings();
    printf("%s | Argon2id params: t_cost_normal=%d, t_cost_brutal=%d, m_cost=%d, parallelism=%d\n",
        VERSION, ARGON2_T_COST_NORMAL, ARGON2_T_COST_BRUTAL, ARGON2_M_COST, ARGON2_P_COST);
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

    // ---- Find or create credentials file ----
    const char *home = getenv("HOME");
    if (!home) { fprintf(stderr, "Could not find HOME environment variable.\n"); return 1; }
    char dirpath[1024], credsfile[1024];
    int dlen = snprintf(dirpath, sizeof(dirpath), "%s/%s", home, DIRNAME);
    if (dlen < 0 || (size_t)dlen >= sizeof(dirpath)) secure_bail_simple(1);
    int clen = snprintf(credsfile, sizeof(credsfile), "%s/%s", dirpath, FILENAME);
    if (clen < 0 || (size_t)clen >= sizeof(credsfile)) secure_bail_simple(1);

    unsigned char firstname[MAXNAME+1] = {0};   // 16 bytes + nul
    unsigned char passphrase[MAXPHRASE+1] = {0};
    unsigned char password[MAXPASS+1] = {0};
    unsigned char pepper[PEPPER_LEN] = {0};
    unsigned char aes_iv[AES_IVLEN] = {0};

    FILE *cf = fopen(credsfile, "rb");
    if (!cf) {
        // ---- FIRST-TIME SETUP ----
        printf("Welcome to TwainPass. First-time setup.\n");
        printf("REMARKS\n");
        printf("| 1. These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("| 2. They can be fake, but you have to be consistent.\n");
        printf("| 3. Both are stored in encrypted form in %s\n", credsfile);

        size_t fn_len = read_line("First name (used as salt, max 16 chars): ", firstname, MAXNAME, 0, NULL);
        if (has_bad_char((char*)firstname, fn_len)) printf("%s", BADCHAR_WARNING);

        // Passphrase entry/check
        size_t ph_len = 0;
        do {
            ph_len = read_line("Passphrase (this acts like a second password, and is stored encrypted on the hard disk): ", passphrase, MAXPHRASE, 1, NULL);
            printf("\n");
            if (ph_len < MINPHRASE) {
                printf("Passphrase must be at least %d bytes. Try again.\n", MINPHRASE);
                continue;
            }
            unsigned char confirm[MAXPHRASE+1] = {0};
            size_t ph2 = read_line("Passphrase (please repeat your passphrase again; we'll tell you if there is a mismatch): ", confirm, MAXPHRASE, 1, NULL);
            printf("\n");
            if (ph_len != ph2 || memcmp(passphrase, confirm, ph_len) != 0) {
                printf("Error: passphrases do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        // Master password entry/check
        size_t pw_len = 0;
        do {
            pw_len = read_line("Master Password (never tell this to anyone, except a judge under court order): ", password, MAXPASS, 1, NULL);
            printf("\n");
            if (pw_len < MINPASS) {
                printf("Master password must be at least %d bytes. Try again.\n", MINPASS);
                continue;
            }
            unsigned char confirm[MAXPASS+1] = {0};
            size_t pw2 = read_line("Master Password (one more time, please; we'll tell you if there's a mismatch): ", confirm, MAXPASS, 1, NULL);
            printf("\n");
            if (pw_len != pw2 || memcmp(password, confirm, pw_len) != 0) {
                printf("Error: passwords do not match. Please try again.\n");
                continue;
            }
            break;
        } while (1);

        printf("\n");
        printf("We're now deriving a pepper from your firstname, passphrase, and password.\n");
        printf("This pepper stored on your hard disk in encrypted form.\n");   
        printf("This may take 10-30 seconds on modern CPUs. On some older systems, it can take a minute or two.\n");
        printf("REMARKS\n");
        printf("| Your password is never stored.\n");
        printf("| You need to remember both your password and your passphrase.\n");
        printf("| Your password cannot be recovered if you forget it.\n");
        printf("| Technically, your passphrase can be recovered as long as you remember the password, and avoid logging out.\n");
        printf("| Nevertheless, you should act like it cannot be recovered.\n");

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
            secure_bail(2, password, sizeof(password), passphrase, sizeof(passphrase), NULL,0, NULL,0, NULL,0);
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
            secure_bail(2, password, sizeof(password), passphrase, sizeof(passphrase), secret, sizeof(secret), NULL,0, NULL,0);
        }}

        memcpy(aes_iv, fname_salt, AES_IVLEN);

        // File format: first name (EOL), then AES(passphrase EOL pepper)
        unsigned char enc_input[MAXPHRASE+2+PEPPER_LEN] = {0};
        size_t enc_len = 0;
        memcpy(enc_input, passphrase, ph_len); enc_len += ph_len;
        enc_input[enc_len++] = '\n';
        memcpy(enc_input+enc_len, pepper, PEPPER_LEN); enc_len += PEPPER_LEN;

        unsigned char ciphertext[enc_len + AES_IVLEN];
        int ciphlen = aes256_cbc_encrypt(secret, aes_iv, enc_input, (int)enc_len, ciphertext);
        if (ciphlen < 0) {
            fprintf(stderr, "AES encryption failed.\n");
            ERR_print_errors_fp(stderr);
            secure_bail(2, password, sizeof(password), passphrase, sizeof(passphrase), secret, sizeof(secret), pepper, sizeof(pepper), NULL,0);
        }

        if (ensure_twain_dir(dirpath) != 0) secure_bail_simple(2);
        umask(0077);

        cf = fopen(credsfile, "wb");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); secure_bail_simple(2);}
        if (fwrite(firstname, 1, fn_len, cf) != fn_len ||
            fputc('\n', cf) == EOF ||
            fwrite(ciphertext, 1, ciphlen, cf) != (size_t)ciphlen) {
            fprintf(stderr, "Failed to write credentials file.\n");
            fclose(cf);
            secure_bail_simple(2);
        }
        fclose(cf);

        printf("\n");
        printf("Your first name (in plaintext) and encrypted passphrase/pepper are now stored at %s\n", credsfile);
        printf("Never tell your password or passphrase to anyone, except under court order.");
        secure_bail(0, secret, sizeof(secret), pepper, sizeof(pepper), password, sizeof(password), passphrase, sizeof(passphrase), NULL,0);
    }

    // ==== OPEN FILE, READ, and BEGIN MAIN MENU ====
    if (cf) rewind(cf);
    unsigned char fname_file[MAXNAME+2] = {0};
    size_t fn_len = 0;
    if (!fgets((char*)fname_file, sizeof(fname_file), cf)) {
        fprintf(stderr, "Failed to read first name from credentials file.\n");
        fclose(cf);
        secure_bail_simple(2);
    }
    fn_len = strcspn((char*)fname_file, "\r\n");
    unsigned char fname_salt[MAXNAME] = {0};
    memcpy(fname_salt, fname_file, fn_len > MAXNAME ? MAXNAME : fn_len);
    memcpy(aes_iv, fname_salt, AES_IVLEN);

    unsigned char ciphertext[(MAXPHRASE+2+PEPPER_LEN) + AES_IVLEN] = {0};
    size_t ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), cf);
    fclose(cf);

    char service[128] = {0};
    {
        char firstname[17];
        memcpy(firstname, fname_file, fn_len);
        printf("Hey %s! Welcome back to TwainPass.\n", firstname);
    }
    printf("REMARKS\n");
    printf("| 1. Your credentials file is stored at %s\n", credsfile);
    printf("| 2. Use service name 'creds-delete' to permanently delete credentials and log out.\n");
    printf("| 3. Use service name 'creds-view' to copy your passphrase and pepper digest for backup.\n\n");

    size_t service_len = read_line("Service name: ", (unsigned char*)service, sizeof(service)-1, 0, NULL);

    // --- creds-delete (DESTROY ALL CREDENTIALS) ---
    if (strcmp(service, "creds-delete") == 0) {
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(fname_salt, 0, sizeof(fname_salt));
        memset(fname_file, 0, sizeof(fname_file));
        if (unlink(credsfile) == 0)
            printf("Credentials securely deleted. Bye!\n");
        else
            perror("Failed to delete credentials file");
        secure_bail_simple(0);
    }

    // --- creds-view (EXPORT RECOVERY DATA) ---
    if (strcmp(service, "creds-view") == 0) {
        unsigned char password_view[MAXPASS+1] = {0};
        size_t pw_len = read_line("Master password (for creds-view): ", password_view, MAXPASS, 1, NULL);
        if (pw_len < MINPASS) {
            printf("Master password must be at least %d bytes. Aborting.\n", MINPASS);
            secure_bail(2, password_view, sizeof(password_view), NULL,0, NULL,0, NULL,0, NULL,0);
        }
        unsigned char secret[HASHLEN] = {0};
        { int rc = argon2id_hash_raw_params(
            ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
            password_view, pw_len,
            fname_salt, MAXNAME,
            secret, HASHLEN,
            "derive secret"
        );
        if (rc != ARGON2_OK) {
            secure_bail(2, password_view, sizeof(password_view), secret, sizeof(secret), NULL,0, NULL,0, NULL,0);
        }}
        unsigned char decrypted[MAXPHRASE+2+PEPPER_LEN+8] = {0};
        int decrypted_len = aes256_cbc_decrypt(secret, aes_iv, ciphertext, (int)ciphertext_len, decrypted);
        if (decrypted_len < 0) decrypted_len = 0;
        // Parse: passphrase (EOL), pepper (remainder)
        char* newline = find_newline_with_pepper_magic(decrypted, decrypted_len);        
        if (!newline) {
            printf("Could not decrypt credentials file!\n");
            secure_bail(2, password_view, sizeof(password_view), secret, sizeof(secret), decrypted, sizeof(decrypted), NULL,0, NULL,0);
        }
        size_t p_off = (size_t)(newline - (char*)decrypted) + 1;
        size_t left = ((size_t)decrypted_len > p_off) ? (size_t)decrypted_len - p_off : 0;
        char passphrase_out[MAXPHRASE+1] = {0};
        memcpy(passphrase_out, decrypted, p_off-1);
        passphrase_out[p_off-1] = 0;
        char pepper_hex[2*PEPPER_LEN+1] = {0};
        to_hex((unsigned char*)decrypted + p_off, left, pepper_hex);

        char clipbuf[MAXPHRASE+2+2*PEPPER_LEN+128];
        snprintf(clipbuf, sizeof(clipbuf), "Passphrase: %s\nPepper digest (hex): %s\n", passphrase_out, pepper_hex);

        // KILL all twain-clip
        kill_old_twain_clip();
        int copied = 0;
        copied = try_clipboard("xclip -selection clipboard 2>/dev/null", clipbuf);
        if (!copied)
            copied = try_clipboard("xsel --clipboard --input 2>/dev/null", clipbuf);
        if (!copied)
            copied = try_clipboard("wl-copy 2>/dev/null", clipbuf);
        if (copied) {
            printf("Credentials exported to clipboard. Paste them in a secure backup document.");
        } else {
            printf("Could not copy credentials to clipboard.\n");
        }
        secure_bail(0, password_view, sizeof(password_view), secret, sizeof(secret), decrypted, sizeof(decrypted), (unsigned char*)clipbuf, sizeof(clipbuf), NULL,0);
    }

    // ==== NORMAL SERVICE PASSWORD WORKFLOW ====
    if (has_bad_char(service, service_len)) printf("%s", BADCHAR_WARNING);
    unsigned char secret[HASHLEN] = {0};
    unsigned char decrypted[MAXPHRASE+2+PEPPER_LEN+8] = {0};
    int decrypted_len = 0;
    size_t pw_len = read_line("Master password: ", password, MAXPASS, 1, NULL);
    printf("\n");
    if (pw_len < MINPASS) {
        printf("Master password must be at least %d bytes. Aborting.\n", MINPASS);
        secure_bail(2, password, sizeof(password), secret, sizeof(secret), NULL,0, NULL,0, NULL,0);
    }
    { int rc = argon2id_hash_raw_params(
        ARGON2_T_COST_NORMAL, ARGON2_M_COST, ARGON2_P_COST,
        password, pw_len,
        fname_salt, MAXNAME,
        secret, HASHLEN,
        "derive secret"
    );
    if (rc != ARGON2_OK) {
        secure_bail(2, password, sizeof(password), secret, sizeof(secret), NULL,0, NULL,0, NULL,0);
    }}

    decrypted_len = aes256_cbc_decrypt(secret, aes_iv, ciphertext, (int)ciphertext_len, decrypted);
    if (decrypted_len < 0) decrypted_len = 0;

    // Find passphrase and pepper in decrypted blob
    char* newline = find_newline_with_pepper_magic(decrypted, decrypted_len);        
    if (!newline) {
        printf("WARNING: Could not decrypt credentials files. Output is still deterministic.\n");
    }
    size_t p_off = newline ? (size_t)(newline - (char*)decrypted) + 1 : (size_t)decrypted_len;
    size_t left = ((size_t)decrypted_len > p_off) ? (size_t)decrypted_len - p_off : 0;

    // ==== FINAL PASSWORD USING SHA3 ====
    unsigned char out_input[HASHLEN + sizeof(DELIM) + PEPPER_LEN + sizeof(DELIM) + 128] = {0};
    size_t off = 0;
    memcpy(out_input, secret, HASHLEN); off += HASHLEN;
    memcpy(out_input+off, DELIM, sizeof(DELIM)-1); off += sizeof(DELIM)-1;
    memcpy(out_input+off, decrypted + p_off, left); off += left;
    memcpy(out_input+off, DELIM, sizeof(DELIM)-1); off += sizeof(DELIM)-1;
    memcpy(out_input+off, service, service_len); off += service_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char out_hash[HASHLEN] = {0};
    if (!mdctx || 1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) ||
        1 != EVP_DigestUpdate(mdctx, fname_salt, MAXNAME) ||
        1 != EVP_DigestUpdate(mdctx, out_input, off) ||
        1 != EVP_DigestFinal_ex(mdctx, out_hash, NULL)) {
        fprintf(stderr, "SHA3 hash error!\n");
        EVP_MD_CTX_free(mdctx);
        secure_bail(2, password, sizeof(password), secret, sizeof(secret), decrypted, sizeof(decrypted), NULL,0, NULL,0);
    }
    EVP_MD_CTX_free(mdctx);

    char outpw[FINALPWLEN+1] = {0};
    base36_tailN(out_hash, outpw, FINALPWLEN);

    // ---- KILL all twain-clip ----
    kill_old_twain_clip();

    int copied = 0;
    copied = try_clipboard("xclip -selection clipboard 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("xsel --clipboard --input 2>/dev/null", outpw);
    if (!copied)
        copied = try_clipboard("wl-copy 2>/dev/null", outpw);

    if (copied) {
        printf("Password copied to clipboard!\n");
        printf("If it's still lurking in the clipboard in 15 seconds, we'll clear the clipboard.\n");
        pid_t pid = fork();
        if (pid == 0) {
            char *argv[3];
            argv[0] = (char*)"twain-clip";
            argv[1] = (char*)outpw;
            argv[2] = NULL;
            execvp("twain-clip", argv);
            _exit(1);
        }
    } else {
        printf("There was an issue spawning the process that's meant to clear the clipboard after 15 seconds.\n");
        printf("Could not copy password to clipboard.\n");
        printf("Please install xclip, xsel, or wl-clipboard to enable clipboard copy.\n");
        printf("For your security, TwainPass will never print your password to the terminal.\n");
    }

    secure_bail(0, secret, sizeof(secret), password, sizeof(password), decrypted, sizeof(decrypted), (unsigned char*)out_hash, sizeof(out_hash), (unsigned char*)outpw, sizeof(outpw));
    return 0;
}
