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

#define HASHLEN      32
#define FINALPWLEN   16
#define DELIM        "::::::::::"
#define BASE36LEN    50
#define CREDS_PATH   "/.nullword/creds.txt"
#define MAXNAME      64  // max allowed for first/last name (alphabetics only)
#define MAXSERVICE   64  // max allowed for service name
#define MAXPASS      64  // max allowed for master password

// Helper: copy only alphabetics, convert to lowercase, up to MAXNAME
void sanitize_name(char *dest, const char *src) {
    size_t di = 0;
    for (size_t si = 0; src[si] && di < MAXNAME; ++si) {
        if (isalpha((unsigned char)src[si])) {
            dest[di++] = tolower((unsigned char)src[si]);
        }
    }
    dest[di] = 0;
}

// Reads input (line), applies sanitize_name, checks for overflow
void get_sanitized_input(const char *prompt, char *buf) {
    char tmp[MAXNAME * 4 + 2]; // allow very large input for filtering
    printf("%s", prompt);
    fflush(stdout);

    if (!fgets(tmp, sizeof(tmp), stdin)) tmp[0] = 0;
    size_t len = strlen(tmp);
    if (len && tmp[len-1] == '\n') tmp[len-1] = 0;

    // Did input overflow buffer? (missing newline at end, buffer full)
    if (len == sizeof(tmp)-1 && tmp[len-1] != '\n') {
        fprintf(stderr, "Input too long (more than %d chars)!\n", MAXNAME);
        exit(1);
    }

    sanitize_name(buf, tmp);
    if (strlen(buf) > MAXNAME) {
        fprintf(stderr, "Sanitized name too long! (max %d alphabetic characters)\n", MAXNAME);
        exit(1);
    }
}

// General input: checks for true overflow (no silent truncation!)
void get_checked_input(const char *prompt, char *buf, size_t maxlen) {
    char tmp[maxlen+2];
    printf("%s", prompt);
    fflush(stdout);

    if (!fgets(tmp, sizeof(tmp), stdin)) tmp[0] = 0;
    size_t len = strlen(tmp);
    if (len && tmp[len-1] == '\n') tmp[len-1] = 0;

    // Overflow check: did we fill tmp without newline?
    if (len == sizeof(tmp)-1 && tmp[len-1] != '\n') {
        fprintf(stderr, "Input too long! (max %zu characters allowed)\n", maxlen);
        exit(1);
    }
    if (strlen(tmp) > maxlen) {
        fprintf(stderr, "Input too long! (max %zu characters allowed)\n", maxlen);
        exit(1);
    }
    strcpy(buf, tmp);
}

void get_hidden_input(const char *prompt, char *buf, size_t maxlen) {
    char tmp[maxlen+2];
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(tmp, sizeof(tmp), stdin)) tmp[0] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    size_t len = strlen(tmp);
    if (len && tmp[len-1] == '\n') tmp[len-1] = 0;

    // Overflow check: did we fill tmp without newline?
    if (len == sizeof(tmp)-1 && tmp[len-1] != '\n') {
        fprintf(stderr, "Password too long! (max %zu characters allowed)\n", maxlen);
        exit(1);
    }
    if (strlen(tmp) > maxlen) {
        fprintf(stderr, "Password too long! (max %zu characters allowed)\n", maxlen);
        exit(1);
    }
    strcpy(buf, tmp);
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

int ensure_nullword_dir() {
    char path[1024];
    snprintf(path, sizeof(path), "%s/.nullword", getenv("HOME"));
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
        printf("Welcome to NullWord!\n");
        printf("Please enter your first and last name below.\n");
        printf("NOTE: These are used as salt and pepper, and never transmitted over the internet.\n");
        printf("NOTE: They can be fake names, but you have to be consistent.\n");
        printf("NOTE: Both are stored as plaintext in %s\n", credsfile);
        printf("NOTE: Only alphabetical characters (A-Z, a-z) will be kept, and all will be converted to lowercase. All other characters will be stripped.\n");
        get_sanitized_input("First name (used as salt): ", firstname);
        get_sanitized_input("Last name (used as pepper): ", lastname);

        if (ensure_nullword_dir() != 0) return 2;

        cf = fopen(credsfile, "w");
        if (!cf) { fprintf(stderr, "Failed to save %s\n", credsfile); return 2; }
        fprintf(cf, "%s\n%s\n", firstname, lastname);
        fclose(cf);

        printf("Thanks, %s! Your chosen names are now stored in %s\n", firstname, credsfile);
    } else {
        // Defensive read: refuse lines that are too long
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

    // Service name (input check)
    get_checked_input("Service name: ", service, MAXSERVICE);

    // Handle logout
    if (strcmp(service, "logout") == 0) {
        return delete_creds(credsfile);
    }

    get_hidden_input("Master password: ", master, MAXPASS);

    // Build input (all buffers are sized for safety)
    char combined[1024] = {0};
    size_t combolen = strlen(firstname) + strlen(lastname) + strlen(service) + strlen(master) + 3*strlen(DELIM);
    if (combolen >= sizeof(combined)) {
        fprintf(stderr, "Combined input too long! Please use shorter inputs.\n");
        return 1;
    }
    snprintf(combined, sizeof(combined), "%s%s%s%s%s%s%s",
        firstname, DELIM, lastname, DELIM, service, DELIM, master);

    uint32_t t_cost = 2;
    uint32_t m_cost = 1126400;
    uint32_t parallelism = 5;
    const char salt[9] = "00000000";
    size_t saltlen = 8;
    unsigned char hash[HASHLEN];

    int rc = argon2id_hash_raw(
        t_cost, m_cost, parallelism,
        combined, strlen(combined),
        salt, saltlen,
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
        printf("For your security, nullword will never print your password to the terminal.\n");
    }

    memset(master, 0, sizeof(master));
    memset(combined, 0, sizeof(combined));
    memset(hash, 0, sizeof(hash));
    memset(password, 0, sizeof(password));

    return 0;
}
