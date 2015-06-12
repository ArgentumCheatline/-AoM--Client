##
## Requires CMake >2.6
##
CMAKE_MINIMUM_REQUIRED(VERSION 2.6 FATAL_ERROR)

##
## The name of the project is "Runner"
##
PROJECT(Runner)

##
## Enable TINY_MODE (COMPILER)
##
SET(CMAKE_BUILD_TYPE "MINSIZEREL")
SET(CMAKE_CXX_FLAGS "/Oy /Zl /EHs-c- /Os /GS- /Gy /Gd /Gm- /nologo /W3")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D _X86_") 

##
## Enable TINY_MODE (LINKER)
##
SET(CMAKE_EXE_LINKER_FLAGS "/MANIFEST:NO /DYNAMICBASE:NO /OPT:REF /SAFESEH:NO /NOLOGO /NODEFAULTLIB") 
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SECTION:.text,ERW /MERGE:.data=.rdata /MERGE:.rdata=.text /MAP:Memory.lst /ignore:4254")
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /ENTRY:Execute@Client@@YAXXZ /SUBSYSTEM:Windows,5.01")

##
## Add the project includes
##
INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/include")

##
## Add the project files
##
FILE(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

##
## Make the executable
##
ADD_EXECUTABLE(Runner ${SOURCES})