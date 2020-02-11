CC=gcc
CCFLAGS= -g -pedantic -std=c99 -Wall -Wextra -Werror
SRC=my_ld.c

.PHONY: clean

all:
	${CC} ${SRC} ${CCFLAGS} -o ${SRC:.c=}

clean:
	${RM} ${SRC:.c=.o} ${SRC:.c=}
