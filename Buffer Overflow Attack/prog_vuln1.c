#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int bar(char *arg, char *out)
{
  strcpy(out, arg);
  return 0;
}

int foo(char *arg)
{
  char buf1[400]="Welcome to ce40442 class.\n";
  char buf2[200];
  bar(arg, buf2);
  printf("%s",buf1);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf(stderr, "prog_vuln1: argc != 2\n");
    exit(EXIT_FAILURE);
  }
  foo(argv[1]);
  return 0;
}
