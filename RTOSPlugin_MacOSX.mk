#
# Makefile for building the J-Link GDB Server RTOS plug-in.
#
# 64-bit targets
# =================
# Invoke 'make' like this:
#
# 		make -f RTOSPlugin_MacOSX.mk release 	# builds only the release version
# 		make -f RTOSPlugin_MacOSX.mk debug 		# builds only the debug version
# 		make -f RTOSPlugin_MacOSX.mk all 	 	 	# builds release and debug versions
# 		make -f RTOSPlugin_MacOSX.mk clean 	 	# removes all the generated binaries
#
# 32-bit targets
# =================
# Invoke 'make' like this:
#
# 		make -f RTOSPlugin_MacOSX.mk TARGET_NAME=i386 release 	# builds only the release version
# 		make -f RTOSPlugin_MacOSX.mk TARGET_NAME=i386 debug 		# builds only the debug version
# 		make -f RTOSPlugin_MacOSX.mk TARGET_NAME=i386 all 	 	 	# builds release and debug versions
# 		make -f RTOSPlugin_MacOSX.mk TARGET_NAME=i386 clean 	 	# removes all the generated binaries
#

#
# List of object files to link
#
OBJECTS  = RTOSPlugin.o

#
# List of libraries to link
#
LIBS     = pthread m edit

#
# Global variables
#
LIB_NAME     = RTOSPlugin

RELEASE_DIR  = Release/$(TARGET_NAME)
DEBUG_DIR    = Debug/$(TARGET_NAME)

RELEASE_LIB_SONAME = lib$(LIB_NAME).so
DEBUG_LIB_SONAME   = lib$(LIB_NAME)_Debug.so

RELEASE_SHARED     = Release/$(TARGET_NAME)/$(RELEASE_LIB_SONAME)
DEBUG_SHARED       = Debug/$(TARGET_NAME)/$(DEBUG_LIB_SONAME)

#
# Preprocessor, compiler and linker flags
#
CPPFLAGS += -D_GNU_SOURCE
CFLAGS   += -fPIC -c -fvisibility=hidden -Wall -Wno-unused-parameter -Wno-unused-variable \
					  -Wno-pointer-sign -Wno-unknown-pragmas -Wno-unused-value -Wno-unused-function \
					  -Wno-switch -Wno-switch-enum -Wno-missing-braces -Wno-pointer-to-int-cast \
						# -Wno-int-to-pointer-cast -Wextra

#
# Handy names for utilities used in this makefile
#
RM    = rm -fr
MKDIR = mkdir -p
ECHO  = echo
CC    = gcc

#
# Set compiler and linker options for the 32-bit build.
#
LDFLAGS += -Wl,-undefined,error
ifeq ($(TARGET_NAME),i386)
	CFLAGS   += -m32 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5
	LDFLAGS  += -m32 -isysroot /Developer/SDKs/MacOSX10.5.sdk -mmacosx-version-min=10.5 
else
	TARGET_NAME = x86_64
endif

#
# Switch for verbose outputs. Invoke make with "V=" on the command line 
# to see more info about the progress of the build process
#
V ?= @  

#
# Tells make where to look for source files
#
VPATH += Src

#
# These are the build goals
#
all: release debug

clean:
	$(V)$(ECHO) "CLEAN"
	$(V)$(RM) $(RELEASE_DIR)/* $(DEBUG_DIR)/*

release: $(RELEASE_SHARED)

debug: $(DEBUG_SHARED)

#
# Figure out what kind of goal we should build
#
DEBUG_GOAL     = 0
RELEASE_GOAL   = 0
ifeq ($(strip $(MAKECMDGOALS)),)
	DEBUG_GOAL   = 1
	RELEASE_GOAL = 1
endif
ifeq ($(findstring all,$(MAKECMDGOALS)),all)
	DEBUG_GOAL   = 1
	RELEASE_GOAL = 1
endif
ifeq ($(findstring release,$(MAKECMDGOALS)),release)
	RELEASE_GOAL = 1
endif
ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
	DEBUG_GOAL   = 1
endif

#
# Include file dependencies
#
ifeq ($(RELEASE_GOAL),1) 
	-include $(addprefix $(RELEASE_DIR)/,$(subst .o,.d,$(OBJECTS)))
endif
ifeq ($(DEBUG_GOAL),1) 
	-include $(addprefix $(DEBUG_DIR)/,$(subst .o,.d,$(OBJECTS)))
endif

#
# Rules to generate dependencies
#
$(RELEASE_DIR)/%.d: %.c	
	$(V)$(ECHO) "DEP $@"
	$(V)$(MKDIR) $(RELEASE_DIR)
	$(V)$(COMPILE.c) -MM -MF $@ $<

$(DEBUG_DIR)/%.d: %.c	
	$(V)$(ECHO) "DEP $@"
	$(V)$(MKDIR) $(DEBUG_DIR)
	$(V)$(COMPILE.c) -D_DEBUG -MM -MT $(subst .d,.o,$@) -MF $@ $<

#
# Rules to generate the object files
#
$(RELEASE_DIR)/%.o: %.c	
	$(V)$(ECHO) "CC $@"
	$(V)$(COMPILE.c) $< -o $@

$(DEBUG_DIR)/%.o: %.c
	$(V)$(ECHO) "CC $@"
	$(V)$(COMPILE.c) -D_DEBUG $< -g -o $@

#
# Generate libraries
# --strip-all: Remove all symbol information from output file.
#
$(RELEASE_SHARED): $(addprefix $(RELEASE_DIR)/, $(OBJECTS))
	$(V)$(ECHO) "LIB $@"
	$(V)$(LINK.o) $(LDFLAGS) -bundle -Wl,-x -Wl,-S $^ -o $@ $(addprefix -l,$(LIBS))

$(DEBUG_SHARED): $(addprefix $(DEBUG_DIR)/, $(OBJECTS))
	$(V)$(ECHO) "LIB $@"
	$(V)$(LINK.o) $(LDFLAGS) -bundle $^ -o $@ $(addprefix -l,$(LIBS))

.PHONY: all clean release debug 
