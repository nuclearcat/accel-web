FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
COPY accel-ppp-webd.go ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN go build -o accel-ppp-webd .

# COPY built executable outside of the container
CMD cp accel-ppp-webd /out/accel-ppp-webd