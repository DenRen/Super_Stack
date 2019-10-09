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
    My_Stack.dumpOn = true;
    My_Stack.dump_file = log;

    StackConstruct (&My_Stack);

    int err = 0, multipl = 5;
    for (int i = 0; i < size * multipl && !err; i++)
        err = push (&My_Stack, (stck::type_Stack)i);

    stck::type_Stack temp = 0;

    for (int i = 0; !pop (&My_Stack, &temp) && !err; i++)
        printf ("%d) %lg\n", i, temp);

    StackDestruct (&My_Stack);
    fclose (log);

    Unit_Test ();

    return 0;
}
