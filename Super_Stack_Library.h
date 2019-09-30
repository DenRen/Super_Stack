//
// Created by tester on 01.10.2019.
//

#ifndef SUPER_STACK_SUPER_STACK_LIBRARY_H
#define SUPER_STACK_SUPER_STACK_LIBRARY_H
#include <cstdio>
#include <cstdlib>
#include <random>
#include <cassert>

#define LOCATION __FILE__, __LINE__, __PRETTY_FUNCTION__
#define PRINT_ERROR(message) printf("\nERROR %s(%d) IN %s: %s\n", LOCATION, message);
#define PRINT_WARNING(message) printf("\nwarning %s(%d) IN %s: %s\n", LOCATION, message);

namespace stck {
    typedef int type_Stack;
    typedef long long canary_t;
    const int UNDERFLOW_STACK = 1431193171; //(const int)'UNFS';
    const int CRITICAL_ERROR = 1128616530;  //(const int)'CERR';
    struct Secure_Stack_t {
        type_Stack *data;   //Хранит начало стека
        size_t size;      //Хранит длину стека в type_Stack
        long number;
        size_t real_size; //В байтах
        int Sec_Level;
        type_Stack *begin; //Хранит истинное начало массива
        canary_t *ptr_canary1;
        canary_t *ptr_canary2;
        canary_t canary1;
        canary_t canary2;
        size_t hash;
        float expansion_coef;
    };
}
static size_t MurmurHash2 (const char *key, size_t len);

/* IBM864
133) ─
134) │
135) ┼
136) ┤
137) ┬
138) ├
139) ┴
140) ┐
141) ┌
142) └
143) ┘
*/
static int Dump (stck::Secure_Stack_t *Stack, FILE *file);

static inline void set_canary_to_Stack (stck::Secure_Stack_t *Stack);

static int CheckingCanary (stck::Secure_Stack_t *Stack, bool write = false);

int StackConstruct (stck::Secure_Stack_t *Stack);

int StackDestruct (stck::Secure_Stack_t *Stack);

int StackPush (stck::Secure_Stack_t *Stack, stck::type_Stack value);

int StackPop (stck::Secure_Stack_t *Stack, stck::type_Stack *value);

static int security_check (stck::Secure_Stack_t *Stack);

static void updating_security_component_values (stck::Secure_Stack_t *Stack);


int Dump (stck::Secure_Stack_t *Stack, FILE *file) {
    static size_t number_calls = 0;

    fprintf (file,
             "=======================================================\n"
             "┌─────────────────────────┬─────────────────┐\n"
             "│Dump: %19zu"            "|       SIZE      |\n"
             "├───────────────────┬─────┘                 |\n", number_calls);
    fprintf (file,
             "|Expension:         |data       %12zu|\n"
             "|            %3.3f  |array      %12zu|\n"
             "└───────────────────┴───────────────────────┘\n", Stack->size, Stack->expansion_coef, Stack->real_size);
    switch (Stack->Sec_Level) {
        case 2: {
            fprintf (file, "┌────────────────────────────────────────┐\n"
                           "│              hash    Calc-hash    equal│\n"
                           "│HASH: %12zu %12zu %8d|\n"
                           "└────────────────────────────────────────┘\n",
                     Stack->hash, MurmurHash2 ((char *) Stack->begin, Stack->real_size),
                     Stack->hash == MurmurHash2 ((char *) Stack->begin, Stack->real_size));
        }
        case 1: {
            fprintf (file,
                     "┌─────────────────────────────────────────────────────┐\n"
                     "│    pointer            *pointer    value_can    equal│\n"
                     "│C1: %12p %12lld %12lld %8d│\n"
                     "│C2: %12p %12lld %12lld %8d│\n"
                     "└─────────────────────────────────────────────────────┘\n\n",
                     Stack->ptr_canary1, *(Stack->ptr_canary1), Stack->canary1,
                     (*(Stack->ptr_canary1) == Stack->canary1),
                     Stack->ptr_canary2, *(Stack->ptr_canary2), Stack->canary2,
                     (*(Stack->ptr_canary2) == Stack->canary2));
        }
    }

    typeof (Stack->size) polovina_size = Stack->size / 2;
    if (sizeof (stck::type_Stack) <= 4) {
        for (size_t i = 0; i < Stack->size; i++) {
            if (i % 2) {
                if (polovina_size + i / 2 + 1 <= Stack->number)
                    fprintf (file, "*");
                else
                    fprintf (file, " ");
                fprintf (file, "[%10ld] = %10lld\n", polovina_size + i / 2, Stack->data[polovina_size + i / 2]);
            } else {
                if (i / 2 <= Stack->number - 1)
                    fprintf (file, "*");
                else
                    fprintf (file, " ");
                fprintf (file, "[%10ld] = %10lld", i / 2, Stack->data[i / 2]);
                if (i + 1 < Stack->size)
                    fprintf (file, " | ");
            }
        }
    } else {
        for (long i = 0; i < Stack->size; i++) {
            if (i <= Stack->number - 1)
                fprintf (file, "*");

            fprintf (file, "[%18ld] = %19lld\n", i, Stack->data[i]);

        }
    }

    printf ("\n");
    number_calls++;
}

//----------------------------------------------------------------------
//! This function does a full security check
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//!
//! @return The execution status of this function
//----------------------------------------------------------------------
int security_check (stck::Secure_Stack_t *Stack) {

    assert (Stack->data != nullptr);
    assert (Stack->begin != nullptr);
    assert (Stack->expansion_coef > 0);
    assert (Stack->size >= (unsigned) Stack->expansion_coef + 1);
    assert (Stack->real_size >= Stack->size);
    assert (Stack->Sec_Level >= 0 && Stack->Sec_Level <= 3);
    assert (Stack->number >= 0);

    //Dump (Stack);

    switch (Stack->Sec_Level) {
        case 2: {
            size_t g = MurmurHash2 ((char *) Stack->begin, Stack->real_size);
            if (Stack->hash != MurmurHash2 ((char *) Stack->begin, Stack->real_size)) {
                PRINT_ERROR ("MurmurHash2")
                return stck::CRITICAL_ERROR;
            }
        }
        case 1: {
            assert (Stack->ptr_canary1 != nullptr);
            assert (Stack->ptr_canary2 != nullptr);
            assert (Stack->ptr_canary1 != Stack->ptr_canary2);

            if (CheckingCanary (Stack)) {
                PRINT_ERROR ("CheckingCanary")
                return stck::CRITICAL_ERROR;
            }
            break;
        }
    }
    if (Stack->Sec_Level >= 2)
        Stack->hash = MurmurHash2 ((char *) Stack->begin, Stack->real_size);
    return 0;
}

//----------------------------------------------------------------------
//! This function popes on the Stack value
//! This function does not crash if a request was made to an empty
//! stack; it simply returns stck::UNDERFLOW_STACK;
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//! @param [in] value This pointer passes the top value of the stack
//!
//! @return The execution status of this function
//----------------------------------------------------------------------
int StackPop (stck::Secure_Stack_t *Stack, stck::type_Stack *value) {
    //
    if (security_check (Stack))
        return stck::CRITICAL_ERROR;

    if (--Stack->number >= 0) {
        *value = Stack->data[Stack->number];
    } else {
        Stack->number++;
        PRINT_WARNING ("Underflow stack!")
        updating_security_component_values (Stack);
        return stck::UNDERFLOW_STACK;
    }
    auto FFFFF = (long) ((typeof (Stack->expansion_coef)) Stack->size / (1 + Stack->expansion_coef));
    if (Stack->number + 1 < (typeof (Stack->number)) ((typeof (Stack->expansion_coef)) Stack->size /
                                                      (1 + Stack->expansion_coef))) { //Сужаем стек
        Stack->size = (size_t) ((typeof (Stack->number)) Stack->size / (1 + Stack->expansion_coef));

        size_t size_stack = Stack->size * sizeof (stck::type_Stack);
        switch (Stack->Sec_Level) {
            case 2:;
            case 1:
                size_stack += 2 * sizeof (stck::canary_t);
        }

        void *temp_ptr = realloc (Stack->begin, size_stack);
        if (temp_ptr == nullptr) {
            PRINT_ERROR("realloc returned nullptr")
            //Dump(Stack);
            return 1;
        }
        Stack->begin = (stck::type_Stack *) temp_ptr;
        Stack->real_size = size_stack;

        switch (Stack->Sec_Level) {
            case 1: {
                set_canary_to_Stack (Stack);
                CheckingCanary (Stack, true);
            }
        }
    }

    updating_security_component_values (Stack);

    return 0;
}

//----------------------------------------------------------------------
//! This function pushes on the Stack value and if necessary,
//! updates the stack size overwriting all security component pointers
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//! @param [in] value The value to put on the stack
//!
//! @return The execution status of this function
//----------------------------------------------------------------------
int StackPush (stck::Secure_Stack_t *Stack, stck::type_Stack value) {
    //
    if (security_check (Stack))
        return stck::CRITICAL_ERROR;
    // Каждый расширенный стек в 1 + expansion_coef больше, чем предыдущий
    if (Stack->number >= Stack->size) { //Расширяем стек
        Stack->size = (typeof (Stack->size)) ((typeof (Stack->expansion_coef)) Stack->size *
                                              (1 + Stack->expansion_coef));
        typeof (Stack->size) size_stack = Stack->size * sizeof (stck::type_Stack);
        switch (Stack->Sec_Level) {
            case 2:;
            case 1:
                size_stack += 2 * sizeof (stck::canary_t);
        }

        void *temp_ptr = realloc (Stack->begin, size_stack);
        if (temp_ptr == nullptr) {
            PRINT_ERROR("realloc returned nullptr")
            //Dump(Stack);
            return 1;
        }
        Stack->begin = (stck::type_Stack *) temp_ptr;
        Stack->real_size = size_stack;

        switch (Stack->Sec_Level) {
            case 2:;
            case 1: {
                set_canary_to_Stack (Stack);
                CheckingCanary (Stack, true);
            }
        }
    }

    Stack->data[Stack->number++] = value;

    updating_security_component_values (Stack);
    //Dump (Stack);
    return 0;
}

//----------------------------------------------------------------------
//! This function updates security component values
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//----------------------------------------------------------------------
void updating_security_component_values (stck::Secure_Stack_t *Stack) {
    switch (Stack->Sec_Level) {
        case 2:;
        case 1: {
            CheckingCanary (Stack, true);
        }
    }
    if (Stack->Sec_Level >= 2)
        Stack->hash = MurmurHash2 ((char *) Stack->begin, Stack->real_size);

}

//----------------------------------------------------------------------
//! This function creates and defines a Stack with security
//! modules which depend on the Stack->Security_Level.
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//!
//! @return The execution status of this function
//----------------------------------------------------------------------
int StackConstruct (stck::Secure_Stack_t *Stack) {
    if (Stack->size <=
        (typeof (Stack->size)) Stack->expansion_coef + 1) {   // Проверка на мин. размер стека, при котором работает
        Stack->size =
                (typeof (Stack->size)) Stack->expansion_coef + 1;      // линейное расширение в 1+expansion_coef раз
    }
    typeof (Stack->size) size_stack = Stack->size * sizeof (stck::type_Stack); //Хранит кол-во байт

    // Создаём дин. массив, длина которого зависит от подключенных уровней безопасностей
    // К примеру, первый уровень требует два объекта типа canary_t
    switch (Stack->Sec_Level) {
        case 2:
            Stack->hash = 0;
        case 1: {   // Канарейка
            size_stack += 2 * sizeof (stck::canary_t);
        }
        case 0: {
            Stack->data = (stck::type_Stack *) calloc (size_stack, 1);
            Stack->begin = Stack->data;
            if (Stack->data == nullptr) {
                PRINT_ERROR("Calloc returned the nullptr");
                return 1;
            }
            Stack->number = 0;
            Stack->real_size = size_stack;

            // Дополнительные действия для модулей безопасности
            if (Stack->Sec_Level >= 1) {
                set_canary_to_Stack (Stack);
                // При помощи истинно рандомного числа запускаю srand()
                std::random_device rd;
                std::uniform_int_distribution<int> uid (0, 34);
                srand (uid (rd));
                CheckingCanary (Stack, true);    // Уставнавливаю нач. зна. канареек
            }

            if (Stack->Sec_Level >= 2)
                Stack->hash = MurmurHash2 ((char *) Stack->begin, Stack->real_size);
        }
    }
    return 0;
}

//----------------------------------------------------------------------
//! This function is emptying to stack
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//!
//! @return The execution status of this function
//----------------------------------------------------------------------
int StackDestruct (stck::Secure_Stack_t *Stack) {
    switch (Stack->Sec_Level) {
        case 2:
            Stack->hash = 0;
        case 1: {
            Stack->ptr_canary1 = nullptr;
            Stack->ptr_canary2 = nullptr;
        }
        case 0: {
            free (Stack->begin);
            Stack->size = 0;
            Stack->begin = nullptr;
        }
    }
    return 0;
}

//----------------------------------------------------------------------
// The program overwrites the values of the canaries and remembers them
//! When bool is false: arranges a canary check them
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//! @param [in] write If false: arranges a canary check them
//!
//! @return     The execution status of this function
//----------------------------------------------------------------------
int CheckingCanary (stck::Secure_Stack_t *Stack, bool write) {
    if (!write) {
        if (Stack->canary1 != *(Stack->ptr_canary1) || Stack->canary2 != *(Stack->ptr_canary2)) {
            return 1;
        }
    }
    Stack->canary1 = (*(Stack->ptr_canary1) = (stck::canary_t) random ());
    Stack->canary2 = (*(Stack->ptr_canary2) = (stck::canary_t) random ());
    return 0;
}

//----------------------------------------------------------------------
//! Sets pointers to canaries at the
//! beginning of an array and at the end of an array Stack->data
//!
//! @param [in] Stack Pointer stck::Secure_Stack_t
//----------------------------------------------------------------------
inline void set_canary_to_Stack (stck::Secure_Stack_t *Stack) {
    // Устанавливаю указатели на канарейки до и после массива
    Stack->ptr_canary1 = (stck::canary_t *) Stack->begin;
    Stack->ptr_canary2 = (stck::canary_t *) ((stck::type_Stack *) ((stck::canary_t *) (Stack->ptr_canary1) + 1) +
                                             Stack->size);
    // Сдвигаю начало до конца канарейки
    Stack->data = (stck::type_Stack *) (Stack->ptr_canary1 + 1);
}

//----------------------------------------------------------------------
//! Calculates a hash using the Murmur Hash 2 algorithm
//! https://ru.wikipedia.org/wiki/MurmurHash2
//! @param [in] key  Pointer to string
//! @param [in] len  Length this string
//!
//! @return     Calculated hash
//----------------------------------------------------------------------
size_t MurmurHash2 (const char *key, size_t len) {
    const unsigned m = 1296126795; //(const unsigned)'MASK';
    const unsigned seed = 0;
    const int r = 24;

    unsigned h = seed ^len;

    const unsigned char *data;
    data = (const unsigned char *) key;
    unsigned k;

    while (len >= 4) {
        k = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    switch (len) {
        case 3:
            h ^= data[2] << 16;
        case 2:
            h ^= data[1] << 8;
        case 1:
            h ^= data[0];
            h *= m;
    }

    switch (len) {
        case 3:
            h ^= data[2] << 16;
        case 2:
            h ^= data[1] << 8;
        case 1:
            h ^= data[0];
            h *= m;
    }
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}

#endif //SUPER_STACK_SUPER_STACK_LIBRARY_H
