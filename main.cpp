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
    My_Stack.dump_file = stdout;

    StackConstruct (&My_Stack);

    int err = 0, multipl = 5;
    for (int i = 0; i < size * multipl && !err; i++)
        err = StackPush (&My_Stack, i);

    stck::type_Stack temp = 0;

    for (int i = 0; !StackPop (&My_Stack, &temp) && !err; i++)
        printf ("%d) %d\n", i, temp);

    StackDestruct (&My_Stack);
    fclose (log);
    Unit_Test ();
    return 0;
}

void Unit_Test () {
    printf ("Stack testing started\n");
    stck::Secure_Stack_t This_Stack = {};
    stck::Secure_Stack_t *Stack = &This_Stack;

    Stack->size = 10;
    Stack->expansion_coef = 0.2;
    Stack->dumpOn = false;
    Stack->dump_file = stdout;


    // Тестируем колличественно
    auto temp_err = 0, number_hack = 0;

    for (Stack->Sec_Level = 0; Stack->Sec_Level <= 2; Stack->Sec_Level++) {
        if (StackConstruct (Stack))
            PRINT_ERROR (" StackConstruct ")

        printf ("The stack with security level  equal %d is designed and initialized.\n", Stack->Sec_Level);

        number_hack = random () % 10000;

        for (size_t j = 1; j < 100000; j *= 10) {

            for (size_t i = 0; i < j; i++) {

                if (j >= number_hack && i == number_hack) {
                    switch (Stack->Sec_Level) {
                        case 2: {
                            Stack->data[i] = random ();
                            temp_err = StackPush (Stack, (stck::type_Stack) random ());
                            if (temp_err)
                                printf ("\nHash verification works!\n");
                            else {
                                printf ("\nHash verification does not work!\n");
                                printf ("Destructor testing :D" "\n");
                                StackDestruct (Stack);
                                return;
                            }
                            break;
                        }
                        case 1: {
                            *Stack->ptr_canary1 = *Stack->ptr_canary1 - 1;
                            temp_err = StackPush (Stack, (stck::type_Stack) random ());
                            if (temp_err)
                                printf ("\nCanary verification works!\n");
                            else {
                                printf ("\nCanary verification does not work!\n");
                                printf ("Destructor testing :D" "\n");
                                StackDestruct (Stack);
                                return;
                            }
                            break;
                        }
                    }
                    updating_security_component_values (Stack);
                }
                temp_err = StackPush (Stack, (stck::type_Stack) random ());
                if (temp_err) {
                    printf ("Destructor testing :D" "\n");
                    StackDestruct (Stack);
                    return;
                }
            }

            auto temp_value = 0;
            while (!(temp_value = StackPop (Stack, &temp_value)));

            if (temp_value != stck::UNDERFLOW_STACK) {
                printf ("Status: %d\n", temp_value);
                printf ("Destructor testing :D" "\n");
                StackDestruct (Stack);
                return;
            }
        }
    }

    printf ("Stack able to withstand large sizes. Nice!\n ");

    Stack->Sec_Level = 1;
    if (StackConstruct (Stack))
        PRINT_ERROR (" StackConstruct ")

    for (size_t i = 0; i < 4564; i++) {
        temp_err = StackPush (Stack, (stck::type_Stack) random ());
        if (temp_err) {
            printf ("Destructor testing :D" "\n");
            StackDestruct (Stack);
            return;
        }
    }

    StackDestruct (Stack);

    printf ("\n" "Stack testing finished. Very good!\n");

}
