# Use the official Golang image as a build stage
# Use --platform to allow buildx to select the correct base image for the target architecture
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
# Changed to golang:1.24-alpine as it's more common, or use 1.24 as you had.
                                                           # $BUILDPLATFORM is a special buildx variable.

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Copy the source code into the container
COPY . .

# Download all dependencies. Dependencies will be cached if the go.mod and
# go.sum files are not changed
RUN go mod download

# Build the Go app
# GOOS and GOARCH are inferred by Docker Buildx based on the target platform.
# We don't need to hardcode GOOS=linux GOARCH=arm64 anymore.
RUN CGO_ENABLED=0 go build -o main .

# Start a new stage from scratch
# Use --platform to allow buildx to select the correct base image for the target architecture
FROM --platform=$BUILDPLATFORM alpine:latest
                                           # Changed to alpine:latest
                                           # $BUILDPLATFORM is a special buildx variable.

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Expose port 6500 to the outside world
EXPOSE 6500

# Command to run the executable
CMD ["./main"]
