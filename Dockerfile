# Use the official Golang image as a build stage
FROM arm64v8/golang:1.24 AS builder
# FROM --platform=linux/arm64 golang:1.24 AS builder

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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o main .

# Start a new stage from scratch
FROM arm64v8/alpine:latest
# FROM --platform=linux/arm64 alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Expose port 6500 to the outside world
EXPOSE 6500

# Command to run the executable
CMD ["./main"]
