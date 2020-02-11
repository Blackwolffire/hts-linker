CC=gcc
CCFLAGS= -save-temps -pedantic -std=c99 -Wall -Wextra -Werror
SRC=main.c

.PHONY: clean

all:
	${CC} ${SRC} ${CCFLAGS} -o ${SRC:.c=}

clean:
	${RM} ${SRC:.c=.o} ${SRC:.c=}
