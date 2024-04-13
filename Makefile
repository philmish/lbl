####################################### BEG ######

NAME := lbl

#------------------------------------------------#
#   INGREDIENTS                                  # 
#------------------------------------------------# 
# SRC_DIR   source directory 
# OBJ_DIR   object directory 
# SRCS      source files 
# OBJS      object files
#
# CC        compiler 
# CFLAGS    compiler flags 
# CPPFLAGS  preprocessor flags

SRC_DIR := src
OBJ_DIR := obj
SRCS := loader.c

# Generates a list of paths to source files
# in the src directory from the list of .c
# files bound to SRCS above.
SRCS := $(SRCS:%=$(SRC_DIR)/%)

# Generates a list of pbject file paths
# One for each targeted source file in
# the src directory.
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CC := gcc
CFLAGS := -Wall -Wextra -Werror
CPPFLAGS := -I include

#------------------------------------------------#
#   UTENSILS                                     #
#------------------------------------------------#
# RM        force remove 
# MAKEFLAGS make flags

RM := rm -f
MAKEFLAGS += --no-print-directory

#------------------------------------------------#
#   RECIPES                                      #
#------------------------------------------------#
# all       default goal
# $(NAME)   linking .o -> binary 
# %.o       compilation .c -> .o 
# clean     remove .o 
# fclean    remove .o + binary 
# re        remake default goal 

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME)
	$(info CREATED $(NAME))

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<
	$(info CREATED $@)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re:
	$(MAKE) fclean
	$(MAKE) all

#------------------------------------------------#
#   SPEC                                         #
#------------------------------------------------#

.PHONY: clean fclean re
.SILENT:

######################################### END ####
