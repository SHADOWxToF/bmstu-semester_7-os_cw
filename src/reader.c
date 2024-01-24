# include <stdio.h>
# include <signal.h>

int flag = 0;

void handler(int s)
{
    flag = 1;
}

int main()
{
    signal(SIGINT, handler);
    FILE *fd[10];
    for (int i = 0; i < 10; ++i)
        fd[i] = fopen("qwerty.txt", "r");
    char c;
    scanf("%c", &c);
    for (int i = 0; i < 10; ++i)
        fclose(fd[i]);
    if (flag)
        printf("Процесс принял сигнал SIGINT\n");
    return 0;
}