#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
usage(void)
{
        printf("Les en bok! Bruk kommandoen './les_bok boknavn'. Tilgjengelige bøker:\n");
        system("ls bok | cut -f1 -d.");
        return EXIT_FAILURE;
}

static char
url_decode_nibble(const char *str)
{
        const char digit = tolower(*str);

        if (digit >= '0' && digit <= '9')
                return digit - '0';
        else if (digit >= 'a' && digit <= 'f')
                return digit - 'a' + 10;
        else
                exit(EXIT_FAILURE);
}

static char
url_decode_char(const char *str)
{
        return url_decode_nibble(str) << 4 | url_decode_nibble(str + 1);
}

static void
url_decode(char *string)
{
        char *dst = string;

        while (*string != 0)
                if (*string == '%') {
                        *dst++ = url_decode_char(++string);
                        string += 2;
                } else
                        *dst++ = *string++;

        *dst = 0;
}

static void
show_file(const char *filename)
{
        char command[128];

        snprintf(command, sizeof(command), "less bok/%s.txt", filename);
        url_decode(command);

        if (setenv("LESSSECURE", "1", 1) != 0)
                exit(EXIT_FAILURE);

        system(command);
}

static bool
filename_ok(const char *filename)
{
        for (; *filename != 0; filename++)
                if (*filename == '&' || *filename == ';' || *filename == '$' || *filename == '|' ||
                    *filename == '<' || *filename == '>' || *filename == '`' || *filename == ' ')
                        return false;
        return true;
}

int
main(int argc, const char *argv[])
{
        if (argc == 1)
                return usage();

        setreuid(geteuid(), geteuid());

        for (int i = 1; argv[i] != NULL && i < argc; i++) {
                const char *filename = argv[i];

                if (filename_ok(filename))
                        show_file(filename);
                else
                        printf("ulovlig filnavn: %s\n", filename);
        }

        return EXIT_SUCCESS;
}
