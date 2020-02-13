CC=gcc
CCFLAGS= -pedantic -std=c99 -Wall -Wextra -Werror
SRC=my_ld.c

.PHONY: clean

my_ld:
	${CC} ${SRC} ${CCFLAGS} -o ${SRC:.c=}

clean:
	${RM} ${SRC:.c=.o} ${SRC:.c=}
