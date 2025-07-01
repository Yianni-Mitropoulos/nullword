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

#define ARGON2_T_COST  2
#define ARGON2_M_COST  1126400
#define ARGON2_P_COST  5

#define BADCHAR_WARNING "\
| WARNING\n\
| 1. Your input contains capital letters, whitespace, or other fancy characters.\n\
| 2. We therefore recommend restarting the process from the beginning.\n\
| 3. We'll use your input as-is, without sanitizing it.\n\
| 4. But it's STRONGLY recommended that you avoid using fancy characters in your names.\n\
|    This is because you'll need to type the exact same names again in the future.\n\
|    Fancy characters can lead to frustration further down the track.\n"

// Secure zero memory using volatile pointer
void secure_memzero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

// Returns 1 if str contains uppercase, whitespace, or punctuation
int has_bad_char(const char *str) {
    int found = 0;
    for (const unsigned char *p = (const unsigned char *)str; *p; ) {
        if (*p < 128) {
            if (isupper(*p) || isspace(*p) || (!isalpha(*p) && !isdigit(*p))) found = 1;
            ++p;
        } else {
            // Accept all multibyte UTF-8
            int clen = 1;
            if ((*p & 0xE0) == 0xC0) clen = 2;
            else if ((*p & 0xF0) == 0xE0) clen = 3;
            else if ((*p & 0xF8) == 0xF0) clen = 4;
            p += clen;
        }
    }
    return found;
}

// UTF-8 safe line editor: mask=1 to show *, 0 for plaintext
void read_line(const char *prompt, char *buf, size_t maxlen, int mask) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO); // raw mode, no echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    size_t len = 0, pos = 0;
    char input[maxlen + 5]; // extra for utf-8 safety
    input[0] = 0;

    while (1) {
        int c = getchar();

        // ENTER
        if (c == '\n' || c == '\r') {
            break;
        }

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
                continue;
            }
        }

        // Backspace (127 or 8)
        if ((c == 127 || c == 8) && pos > 0) {
            size_t orig = pos;
            do { pos--; } while (pos > 0 && ((input[pos] & 0xC0) == 0x80));
            memmove(&input[pos], &input[orig], len - orig + 1);
            len -= orig - pos;
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
                for (size_t i = pos; i < len; ) {
                    putchar('*');
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
        }
    }
    input[len] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    if (len >= maxlen) {
        fprintf(stderr, "Input too long! (max %zu bytes)\n", maxlen - 1);
        exit(1);
    }
    strncpy(buf, input, maxlen);
    buf[maxlen] = 0;
}

// Overwrite and delete a file for security (best effort, not perfect on SSDs)
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
    // Overwrite with zeroes
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
    fsync(fd); // Force write to disk
    close(fd);
    // Now unlink
    if (unlink(path) == 0) {
        printf("Credentials securely deleted. Bye!\n");
        return 0;
    } else {
        perror("Failed to delete credentials file");
        return 1;
    }
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

int main() {
    setlocale(LC_ALL, "");
    printf("%s | ", VERSION);
    printf("Argon2id params: t_cost=%d, m_cost=%d, parallelism=%d\n", ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST);

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Could not find HOME environment variable.\n");
        return 1;
    }

    // Use explicit buffer sizes and check for overflow
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

    char firstname[MAXNAME+1] = {0};
    char lastname[MAXNAME+1] = {0};

    FILE *cf = fopen(credsfile, "r");
    if (!cf) {
        printf("Please enter your first and last name below.\n");
        printf("| REMARKS\n");
        printf("| 1. These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("| 2. They can be fake names, but you have to be consistent.\n");
        printf("| 3. Both are stored as plaintext in %s\n", credsfile);
        umask(0077); // Ensure creds file is 0600 perms
        read_line("First name (used as salt): ", firstname, MAXNAME, 0);
        if (has_bad_char(firstname)) printf("%s", BADCHAR_WARNING);
        read_line("Last name (used as pepper): ", lastname, MAXNAME, 0);
        if (has_bad_char(lastname)) printf("%s", BADCHAR_WARNING);

        if (ensure_nullword_dir(dirpath) != 0) return 2;

        cf = fopen(credsfile, "w");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); return 2; }
        fprintf(cf, "%s\n%s\n", firstname, lastname);
        fclose(cf);

        printf("Thanks, %s! Your chosen names are now stored in %s\n\n", firstname, credsfile);
    } else {
        if (!fgets(firstname, sizeof(firstname), cf)) return 3;
        if (strchr(firstname, '\n') == NULL && !feof(cf)) {
            fprintf(stderr, "Credentials file corrupt: first name too long.\n");
            fclose(cf);
            return 3;
        }
        if (!fgets(lastname, sizeof(lastname), cf)) return 3;
        if (strchr(lastname, '\n') == NULL && !feof(cf)) {
            fprintf(stderr, "Credentials file corrupt: last name too long.\n");
            fclose(cf);
            return 3;
        }
        size_t l = strlen(firstname); if (l && firstname[l-1] == '\n') firstname[l-1] = 0;
        l = strlen(lastname); if (l && lastname[l-1] == '\n') lastname[l-1] = 0;
        fclose(cf);
        printf("Hey, %s!\n", firstname);
        printf(
            "| REMARKS\n"
            "| 1. Your credentials file is stored at %s\n"
            "| 2. You can use a service name of 'logout' to delete your credentials file.\n",
        credsfile);
    }

    char service[MAXSERVICE+1];
    char master[MAXPASS+1];

    // Service name first, then password
    read_line("Service name: ", service, MAXSERVICE, 0);
    if (has_bad_char(service)) printf("%s", BADCHAR_WARNING);

    if (strcmp(service, "logout") == 0) {
        secure_memzero(service, sizeof(service));
        secure_memzero(firstname, sizeof(firstname));
        secure_memzero(lastname, sizeof(lastname));
        return secure_delete_file(credsfile);
    }

    read_line("Master password: ", master, MAXPASS, 1);

    char combined[1024] = {0};
    size_t combolen = strlen(firstname) + strlen(lastname) + strlen(service) + strlen(master) + 3*strlen(DELIM);
    if (combolen >= sizeof(combined)) {
        fprintf(stderr, "Combined input too long! Please use shorter inputs.\n");
        return 1;
    }
    snprintf(combined, sizeof(combined), "%s%s%s%s%s%s%s",
        firstname, DELIM, lastname, DELIM, service, DELIM, master);

    printf("Hashing: please wait...\n");
    fflush(stdout);

    unsigned char hash[HASHLEN];

    int rc = argon2id_hash_raw(
        ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST,
        combined, strlen(combined),
        "00000000", 8,
        hash, HASHLEN);

    secure_memzero(master, sizeof(master)); // Extra paranoia

    if (rc != ARGON2_OK) {
        fprintf(stderr, "Argon2 error: %s\n", argon2_error_message(rc));
        if (rc == ARGON2_MEMORY_TOO_LITTLE || rc == ARGON2_MEMORY_ALLOCATION_ERROR)
            fprintf(stderr, "Not enough memory for Argon2 hash computation. Try closing other programs. If that doesn't help, you might need more RAM.\n");
        secure_memzero(combined, sizeof(combined));
        return 2;
    }

    char password[FINALPWLEN+1] = {0};
    base36_tailN(hash, password, FINALPWLEN);

    int copied = 0;
    copied = try_clipboard("xclip -selection clipboard 2>/dev/null", password);
    if (!copied)
        copied = try_clipboard("xsel --clipboard --input 2>/dev/null", password);
    if (!copied)
        copied = try_clipboard("wl-copy 2>/dev/null", password);

    if (copied) {
        printf("Password copied to clipboard!\n");
    } else {
        printf("Could not copy password to clipboard.\n");
        printf("Please install xclip, xsel, or wl-clipboard to enable clipboard copy.\n");
        printf("For your security, nullword will never print your password to the terminal.\n");
    }

    // Securely zero sensitive memory
    secure_memzero(master, sizeof(master));
    secure_memzero(combined, sizeof(combined));
    secure_memzero(hash, sizeof(hash));
    secure_memzero(password, sizeof(password));
    secure_memzero(service, sizeof(service));
    secure_memzero(firstname, sizeof(firstname));
    secure_memzero(lastname, sizeof(lastname));

    return 0;
}
