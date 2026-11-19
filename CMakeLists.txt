cmake_minimum_required(VERSION 3.20)
project(StormVRServer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/W3 /utf-8)
endif()

# ------------------------------------------------------------------
# NVENC opcional: define HAVE_NVENC se o SDK estiver presente
# Baixe em: https://developer.nvidia.com/nvidia-video-codec-sdk
# Extraia e aponte NVENC_SDK para a pasta raiz do SDK.
# ------------------------------------------------------------------
set(NVENC_SDK "" CACHE PATH "Pasta raiz do NVENC SDK (opcional)")
if(NVENC_SDK AND EXISTS "${NVENC_SDK}/Interface/nvEncodeAPI.h")
  message(STATUS "NVENC SDK encontrado: ${NVENC_SDK}")
  set(HAVE_NVENC ON)
else()
  message(STATUS "NVENC SDK não encontrado — compilando sem aceleração de hardware (fallback CPU)")
  set(HAVE_NVENC OFF)
endif()

add_executable(stormvr_server src/stormvr_server.cpp)
target_link_libraries(stormvr_server PRIVATE ws2_32 d3d11 dxgi)
if(HAVE_NVENC)
  target_include_directories(stormvr_server PRIVATE "${NVENC_SDK}/Interface")
  target_compile_definitions(stormvr_server PRIVATE HAVE_NVENC)
  # nvEncodeAPI64.dll é carregada em runtime via LoadLibrary — não precisa .lib
endif()
set_target_properties(stormvr_server PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
