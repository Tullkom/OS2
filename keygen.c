#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char uchar;

uint32_t lic_hash(char *user, char *expires)
{
    uint32_t h;
    uchar *p;

    h = 0x4f5a521f;
    for (p = (uchar *)user; *p != '\0'; p = p + 1) {
        h = (uint32_t)*p + h * 0x1f;
    }
    for (p = (uchar *)expires; *p != '\0'; p = p + 1) {
        h = (h ^ *p) << 3 | h >> 0x1d;
    }
    return h;
}

void derive_key(char *user, char *expires, char *out)
{
    uint32_t k;
    size_t i;
    static const unsigned char off[11] = {0x38, 0x1b, 0x35, 0x23, 0x39, 0x34, 0x2f, 0x1a, 0x37, 0x34, 0x1a};

    k = lic_hash(user, expires);
    for (i = 0; i < 0xb; i = i + 1) {
        k = k * 0x41c64e6d + 0x3039;
        out[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
              [((k >> 0x10 & 0xff) + off[i]) % 0x3e];
    }
    out[0xb] = '\0';
    return;
}

int main(int argc, char **argv)
{
    char out[12];

    if (argc != 3) {
        fprintf(stderr, "Usage: keygen <user> <expires>\n");
        return 1;
    }

    derive_key(argv[1], argv[2], out);
    FILE *f;
    f = fopen("license.key", "w");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fprintf(f, "USER=%s\n", argv[1]);
    fprintf(f, "EXPIRES=%s\n", argv[2]);
    fprintf(f, "KEY=%s\n", out);
    fclose(f);

    return 0;
}