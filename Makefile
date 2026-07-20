# cloud-serv — Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread \
           -Iinclude \
           -Ilibs

# -lssl -lcrypto: password hashing (PBKDF2), SHA-256, CSPRNG in security/crypto
# -lsqlite3: system SQLite (libsqlite3-dev)
LDFLAGS = -lpthread -lssl -lcrypto -lsqlite3

# Project sources
PROJECT_SOURCES = src/main.cpp \
                  src/core/config.cpp \
                  src/db/database.cpp \
                  src/db/models.cpp \
                  src/http/middleware.cpp \
                  src/routes/auth.cpp \
                  src/routes/files.cpp \
                  src/routes/notes.cpp \
                  src/routes/uploads.cpp \
                  src/routes/static_files.cpp \
                  src/security/crypto.cpp \
                  src/security/request_auth.cpp \
                  src/security/rate_limiter.cpp \
                  src/security/sanitizer.cpp \
                  src/security/validator.cpp \
                  src/storage/file_store.cpp \
                  src/utils/logger.cpp \
                  src/utils/string_utils.cpp

# Object files
PROJECT_OBJECTS = $(PROJECT_SOURCES:.cpp=.o)

TARGET = cloud_serv

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(PROJECT_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^ $(LDFLAGS)

# Compile C++ sources
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	find src -name "*.o" -delete
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)
