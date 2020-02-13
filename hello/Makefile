CC=gcc
CCFLAGS= -std=c99 -Wall -Wextra -Werror
SRC=hello.c

.PHONY: clean

hello:
	${CC} ${SRC} ${CCFLAGS} -o ${SRC:.c=}

clean:
	${RM} ${SRC:.c=.o} ${SRC:.c=}
