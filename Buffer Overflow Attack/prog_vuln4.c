#include <stdio.h>
#include <stdlib.h>

char binsh[] = "/bin/sh";

int main(void) {
    char name[0x10];
    system("echo -n \"What's your name? \"");
    scanf("%s", name);
    printf("Welcome to ce40441 class, %s!\n", name);
    return 0;
}