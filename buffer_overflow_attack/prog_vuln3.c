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
  printf(buf1);
  return 0;
}

int main(int argc, char *argv[])
{
  char cmd[20]="/bin/echo";
  char *msg[]={"prog_vuln3: argc != 2\n",NULL};
  if (argc != 2)
    execv(cmd,msg);
  foo(argv[1]);
  return 0;
}
