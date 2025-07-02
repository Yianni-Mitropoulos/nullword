#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define CLIPBOARD_TIMEOUT 15

int check_clipboard(const char *cmd, const char *pw) {
    char buf[256] = {0};
    FILE *fp = popen(cmd, "r");
    if (!fp) return 0;
    if (fgets(buf, sizeof(buf), fp) == NULL) { pclose(fp); return 0; }
    pclose(fp);
    // Strip trailing newline
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = 0;
    return strcmp(buf, pw) == 0;
}
void clear_clipboard(const char *cmd) {
    FILE *fp = popen(cmd, "w");
    if (!fp) return;
    fputs("\n", fp);
    pclose(fp);
    printf("Clipboard cleared!\n");
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    const char *pw = argv[1];
    sleep(CLIPBOARD_TIMEOUT);

    // Check and clear using whichever clipboard utility is present
    struct { const char *get, *set; } clip_cmds[] = {
        {"xclip -o -selection clipboard 2>/dev/null",   "xclip -selection clipboard 2>/dev/null"},
        {"xsel --clipboard --output 2>/dev/null",       "xsel --clipboard --input 2>/dev/null"},
        {"wl-paste 2>/dev/null",                        "wl-copy 2>/dev/null"}
    };
    for (int i = 0; i < 3; ++i) {
        if (check_clipboard(clip_cmds[i].get, pw))
            clear_clipboard(clip_cmds[i].set);
    }
    return 0;
}
