#include <cstdio>

#include "Super_Stack_Library.h"


int main () {
    int size = 10;
    FILE *log = fopen ("log.txt", "w");
    if (log == nullptr) {
        printf ("Error open file\n");
        return 0;
    }

    stck::Secure_Stack_t My_Stack = {};

    My_Stack.size = size;
    My_Stack.Sec_Level = 2;
    My_Stack.expansion_coef = 0.2;

    StackConstruct (&My_Stack);
    Dump (&My_Stack, log);

    int err = 0, multipl = 20;
    for (int i = 0; i < size * multipl && !err; i++) {
        err = StackPush (&My_Stack, 17 + i);

        if (i % (multipl / 2) == 0) {
            Dump (&My_Stack, log);
        }
    }
    stck::type_Stack temp = 0;
    int state = 0;

    printf ("\n------------------------------------------\n"
            "\n------------------------------------------\n");
    Dump (&My_Stack, log);
    for (int i = 0; !StackPop (&My_Stack, &temp) && !err; i++) {
        if (i % (multipl / 2)) {
            Dump (&My_Stack, log);
        }
    }
    Dump (&My_Stack, log);
    StackDestruct (&My_Stack);
    fclose(log);
    return 0;
}
