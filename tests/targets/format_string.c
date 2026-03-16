/*
 * format_string.c — Test target: format string vulnerability.
 * Passes user-controlled input directly to printf.
 */
#include <stdio.h>
#include <string.h>

static void log_message(const char *msg)
{
    /* Bug: user input used as format string */
    printf(msg);
    printf("\n");
}

int main(void)
{
    char input[512];
    if (fgets(input, sizeof(input), stdin)) {
        /* Remove trailing newline */
        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n')
            input[len - 1] = '\0';

        /* Gate: only hit vulnerable path with prefix */
        if (len > 4 && input[0] == 'L' && input[1] == 'O' &&
            input[2] == 'G' && input[3] == ':') {
            log_message(input + 4);
        }
    }
    return 0;
}
