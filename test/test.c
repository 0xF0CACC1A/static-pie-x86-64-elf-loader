#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

volatile int global_var = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *thread(void *arg) {
        static int static_var=1;
        int my_arg = *((int *)arg);
        while (1) {
                srand(time(NULL));

                pthread_mutex_lock(&lock);

                if (static_var >= 5 && my_arg == 1){
                        printf("Whoops static var is %d and thread #%d is gonna die!\n", static_var, my_arg);
                        pthread_mutex_unlock(&lock);
                        return NULL;
                }

                if (static_var >= 10 && my_arg == 2){
                        printf("Whoops static var is %d and thread #%d is gonna die!\n", static_var, my_arg);
                        exit(EXIT_SUCCESS);
                }

                static_var+=my_arg;
                global_var++;
                printf("random number: %d\nmy arg: %d\nstatic var: %d\nglobal var: %d\n\n", rand() % 100, my_arg, static_var, global_var);

                pthread_mutex_unlock(&lock);

                sleep(1);
        }
}

int main(int argc, char **argv){
        const char* s = getenv("PATH");
        printf("PATH :%s\n", (s != NULL) ? s : "getenv returned NULL");

        printf("Hi %s! you are running %s\nWhat's your surname?: ", argv[1], getauxval(AT_EXECFN));
        fflush(stdout);

        char buf[100];
        scanf("%s", buf);
        buf[strlen(buf)] = '\0';

        printf("Hi %s %s! Now I'm gonna start two threads!\n", argv[1], buf);
        pthread_t t1, t2;
        const int i = 1, j=2;
        pthread_create(&t1, NULL, thread, (void *)&i);
        pthread_create(&t2, NULL, thread, (void *)&j);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        exit(EXIT_SUCCESS);
}
