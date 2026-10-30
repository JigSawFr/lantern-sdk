# liblantern_jni.so, the JNI side of the Kotlin sketch, over Lantern::c_static.
# Built by c/tests where a JDK is, and on its own with the NDK:
#   cmake -S c/bindings/kotlin/src/main/c -B build/jni \
#     -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a
cmake_minimum_required(VERSION 3.28)
project(LanternJni LANGUAGES C CXX)

if (NOT TARGET Lantern::c_static)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../.. ${CMAKE_CURRENT_BINARY_DIR}/lantern-c)
endif ()

add_library(lantern_jni SHARED lantern_jni.c)
set_target_properties(lantern_jni PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    # The C++ library inside needs the C++ runtime
    LINKER_LANGUAGE CXX)
# The NDK's sysroot has jni.h; a desktop takes its JDK's
if (NOT ANDROID)
    find_package(JNI REQUIRED)
    target_include_directories(lantern_jni SYSTEM PRIVATE ${JNI_INCLUDE_DIRS})
endif ()
target_link_libraries(lantern_jni PRIVATE Lantern::c_static)
if (COMMAND lantern_c_warnings)
    lantern_c_warnings(lantern_jni)
endif ()
