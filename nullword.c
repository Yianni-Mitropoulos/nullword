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

#define HASHLEN        32
#define FINALPWLEN     16
#define DELIM          "::::::::::"
#define BASE36LEN      50
#define CREDS_PATH     "/.zeropass/creds.txt"
#define MAXNAME        64    // for first/last name
#define MAXSERVICE     64    // for service name
#define MAXPASS        64    // for master password

// Argon2id parameters as macros
#define ARGON2_T_COST  2
#define ARGON2_M_COST  1126400
#define ARGON2_P_COST  5

// Helper: Copy only alphabetics, convert to lowercase, up to maxlen
void sanitize_alpha_lower(char *dest, const char *src, size_t maxlen) {
    size_t di = 0;
    for (size_t si = 0; src[si] && di < maxlen; ++si) {
        if (isalpha((unsigned char)src[si]) && ((unsigned char)src[si]) < 128) {
            dest[di++] = tolower((unsigned char)src[si]);
        }
    }
    dest[di] = 0;
}

// Line editor for all fields (mask=1 for password, 0 for normal fields)
void read_line(const char *prompt, char *buf, size_t maxlen, int mask, int sanitize) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO); // raw mode, no echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char input[maxlen+2];
    size_t len = 0, pos = 0;
    input[0] = 0;

    while (1) {
        int c = getchar();

        // ENTER key
        if (c == '\n' || c == '\r') {
            break;
        }

        // Handle arrow keys
        if (c == 27) { // ESC
            int c2 = getchar();
            if (c2 == '[') {
                int c3 = getchar();
                // Left Arrow
                if (c3 == 'D' && pos > 0) {
                    printf("\033[1D");
                    fflush(stdout);
                    pos--;
                }
                // Right Arrow
                else if (c3 == 'C' && pos < len) {
                    printf("\033[1C");
                    fflush(stdout);
                    pos++;
                }
                continue;
            }
        }
        // Backspace (127 or 8)
        if ((c == 127 || c == 8) && pos > 0) {
            memmove(&input[pos-1], &input[pos], len-pos+1);
            len--;
            pos--;
            printf("\033[1D");
            printf("\033[s"); // save cursor
            if (mask) {
                for (size_t i = pos; i < len; ++i)
                    putchar('*');
            } else {
                for (size_t i = pos; i < len; ++i)
                    putchar(input[i]);
            }
            putchar(' ');
            printf("\033[u"); // restore cursor
            fflush(stdout);
            continue;
        }
        // Insert char (print * if mask)
        if ((unsigned char)c >= 32 && (unsigned char)c <= 126 && len < maxlen) {
            memmove(&input[pos+1], &input[pos], len-pos+1);
            input[pos] = c;
            len++;
            printf("\033[s"); // save cursor
            if (mask) {
                for (size_t i = pos; i < len; ++i)
                    putchar('*');
            } else {
                for (size_t i = pos; i < len; ++i)
                    putchar(input[i]);
            }
            putchar(' ');
            printf("\033[u"); // restore cursor
            printf("\033[1C");
            fflush(stdout);
            pos++;
        }
    }

    input[len] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    // Sanitization step if needed
    if (sanitize) {
        sanitize_alpha_lower(buf, input, maxlen);
    } else {
        strncpy(buf, input, maxlen);
        buf[maxlen] = 0;
    }
}

// Reads sanitized name field (mask=0)
void get_sanitized_input(const char *prompt, char *buf, size_t maxlen) {
    read_line(prompt, buf, maxlen, 0, 1);
    if (strlen(buf) > maxlen) {
        fprintf(stderr, "Sanitized input too long! (max %zu alphabetic characters)\n", maxlen);
        exit(1);
    }
}

// Reads service name (mask=0, sanitizes to alpha lowercase)
void get_sanitized_service(const char *prompt, char *buf, size_t maxlen) {
    read_line(prompt, buf, maxlen, 0, 1);
    if (strlen(buf) > maxlen) {
        fprintf(stderr, "Sanitized service name too long! (max %zu alphabetic characters)\n", maxlen);
        exit(1);
    }
}

// Reads password (mask=1), no sanitization
void get_hidden_input(const char *prompt, char *buf, size_t maxlen) {
    read_line(prompt, buf, maxlen, 1, 0);
    if (strlen(buf) > maxlen) {
        fprintf(stderr, "Password too long! (max %zu characters allowed)\n", maxlen);
        exit(1);
    }
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

int ensure_zeropass_dir() {
    char path[1024];
    snprintf(path, sizeof(path), "%s/.zeropass", getenv("HOME"));
    struct stat st;
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == -1) {
            fprintf(stderr, "Failed to create %s\n", path);
            return 1;
        }
    }
    return 0;
}

int delete_creds(const char *credsfile) {
    if (unlink(credsfile) == 0) {
        printf("Credentials deleted. Bye!\n");
        return 0;
    } else if (errno == ENOENT) {
        printf("No credentials file to delete.\n");
        return 0;
    } else {
        perror("Failed to delete credentials file");
        return 1;
    }
}

int main() {
    char firstname[MAXNAME+1] = {0};
    char lastname[MAXNAME+1] = {0};
    char credsfile[1024];
    snprintf(credsfile, sizeof(credsfile), "%s%s", getenv("HOME"), CREDS_PATH);

    FILE *cf = fopen(credsfile, "r");
    if (!cf) {
        printf("Welcome to ZeroPass!\n");
        printf("Please enter your first and last name below.\n");
        printf("NOTE: These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("NOTE: They can be fake names, but you have to be consistent.\n");
        printf("NOTE: Both are stored as plaintext in %s\n", credsfile);
        printf("NOTE: Only A-Z and a-z will be kept for names and service names (all will be lowercased, all else stripped).\n");
        get_sanitized_input("First name (used as salt): ", firstname, MAXNAME);
        get_sanitized_input("Last name (used as pepper): ", lastname, MAXNAME);

        if (ensure_zeropass_dir() != 0) return 2;

        cf = fopen(credsfile, "w");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); return 2; }
        fprintf(cf, "%s\n%s\n", firstname, lastname);
        fclose(cf);

        printf("Thanks, %s! Your chosen names are now stored in %s\n", firstname, credsfile);
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
        printf("Hey, %s! You can use a service name of 'logout' to delete your credentials file.\n", firstname);
    }

    char service[MAXSERVICE+1];
    char master[MAXPASS+1];

    get_sanitized_service("Service name: ", service, MAXSERVICE);

    if (strcmp(service, "logout") == 0) {
        return delete_creds(credsfile);
    }

    get_hidden_input("Master password: ", master, MAXPASS);

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

    if (rc != ARGON2_OK) {
        fprintf(stderr, "Argon2 error: %s\n", argon2_error_message(rc));
        if (rc == ARGON2_MEMORY_TOO_LITTLE || rc == ARGON2_MEMORY_ALLOCATION_ERROR)
            fprintf(stderr, "Not enough memory for Argon2 hash computation. Try closing other programs. If that doesn't help, you might need more RAM.\n");
        memset(master, 0, sizeof(master));
        memset(combined, 0, sizeof(combined));
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
        printf("For your security, zeropass will never print your password to the terminal.\n");
    }

    memset(master, 0, sizeof(master));
    memset(combined, 0, sizeof(combined));
    memset(hash, 0, sizeof(hash));
    memset(password, 0, sizeof(password));

    return 0;
}